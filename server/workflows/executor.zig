//! Workflow Execution Engine
//!
//! Orchestrates execution of workflow plans (DAGs) with dependency tracking,
//! parallel execution, and streaming output.

const std = @import("std");
const plan = @import("plan.zig");
const db = @import("db");
const workflows_dao = db.workflows;
const llm_executor_mod = @import("llm_executor.zig");
const json = @import("../lib/json.zig");

fn buildToolLogPayload(
    allocator: std.mem.Allocator,
    tool_name: []const u8,
    tool_input: ?[]const u8,
    tool_output: ?[]const u8,
    success: ?bool,
) ![]const u8 {
    var list = std.ArrayList(u8){};
    errdefer list.deinit(allocator);

    const writer = list.writer(allocator);
    try writer.writeByte('{');
    try json.writeKey(writer, "tool_name");
    try json.writeString(writer, tool_name);
    if (tool_input) |input| {
        try json.writeSeparator(writer);
        try json.writeKey(writer, "tool_input");
        try json.writeString(writer, input);
    }
    if (tool_output) |output| {
        try json.writeSeparator(writer);
        try json.writeKey(writer, "tool_output");
        try json.writeString(writer, output);
    }
    if (success) |ok| {
        try json.writeSeparator(writer);
        try json.writeKey(writer, "success");
        try json.writeBool(writer, ok);
    }
    try writer.writeByte('}');

    return try list.toOwnedSlice(allocator);
}

const ParallelWorker = struct {
    step: *const plan.Step,
    // Parent thread allocator (not used for cross-thread writes)
    allocator: std.mem.Allocator,
    // Event propagation from worker
    event_callback: ?EventCallback = null,
    event_ctx: ?*anyopaque = null,

    // Outcome fields (written by worker)
    status: StepStatus = .failed,
    exit_code: ?i32 = null,
    turns_used: ?i32 = null,
    tokens_in: ?i32 = null,
    tokens_out: ?i32 = null,
    // Serialized artifacts copied using c_allocator for cross-thread safety
    output_json_c: ?[]u8 = null,
    error_message_c: ?[]u8 = null,
    started_at: i64 = 0,
    completed_at: i64 = 0,
};

fn parallelWorkerMain(worker: *ParallelWorker, db_pool: ?*db.Pool, run_id: i32) void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var exec = Executor.init(arena.allocator(), db_pool, run_id);
    if (worker.event_callback) |cb| {
        exec.setEventCallback(cb, worker.event_ctx);
    }
    var result = exec.executeStep(worker.step) catch {
        worker.status = .failed;
        worker.exit_code = null;
        worker.turns_used = null;
        worker.tokens_in = null;
        worker.tokens_out = null;
        worker.error_message_c = null;
        worker.started_at = std.time.timestamp();
        worker.completed_at = std.time.timestamp();
        return;
    };

    worker.status = result.status;
    worker.exit_code = result.exit_code;
    worker.turns_used = result.turns_used;
    worker.tokens_in = result.tokens_in;
    worker.tokens_out = result.tokens_out;
    // Serialize output and copy to c_allocator for safe transfer
    if (result.output) |outv| {
        const s = json.valueToString(arena.allocator(), outv) catch null;
        if (s) |sv| {
            const dupe = std.heap.c_allocator.dupe(u8, sv) catch null;
            worker.output_json_c = dupe;
        } else worker.output_json_c = null;
    } else worker.output_json_c = null;

    if (result.error_message) |msg| {
        worker.error_message_c = std.heap.c_allocator.dupe(u8, msg) catch null;
    } else worker.error_message_c = null;
    worker.started_at = result.started_at;
    worker.completed_at = result.completed_at;
    result.deinit(arena.allocator());
}

/// Step execution status
pub const StepStatus = enum {
    pending, // Not yet started
    running, // Currently executing
    succeeded, // Completed successfully
    failed, // Failed with error
    skipped, // Skipped due to dependency failure
    cancelled, // Manually cancelled

    pub fn toString(self: StepStatus) []const u8 {
        return switch (self) {
            .pending => "pending",
            .running => "running",
            .succeeded => "succeeded",
            .failed => "failed",
            .skipped => "skipped",
            .cancelled => "cancelled",
        };
    }
};

/// Step execution result
pub const StepResult = struct {
    step_id: []const u8,
    status: StepStatus,
    exit_code: ?i32,
    output: ?std.json.Value,
    error_message: ?[]const u8,
    turns_used: ?i32,
    tokens_in: ?i32,
    tokens_out: ?i32,
    started_at: i64, // Unix timestamp
    completed_at: i64, // Unix timestamp

    fn freeJsonValue(allocator: std.mem.Allocator, v: *std.json.Value) void {
        switch (v.*) {
            .null, .bool, .integer, .float, .number_string => {},
            .string => |s| allocator.free(s),
            .array => |arr| {
                for (arr.items) |*it| freeJsonValue(allocator, it);
                arr.deinit();
            },
            .object => |obj| {
                var it = obj.iterator();
                // Values own their memory, keys are not owned here
                while (it.next()) |entry| {
                    freeJsonValue(allocator, entry.value_ptr);
                }
                var m = obj;
                m.deinit();
            },
        }
    }

    pub fn deinit(self: *StepResult, allocator: std.mem.Allocator) void {
        allocator.free(self.step_id);
        if (self.error_message) |msg| {
            allocator.free(msg);
        }
        // Deallocate output JSON if present
        if (self.output) |output| {
            var tmp = output;
            freeJsonValue(allocator, &tmp);
        }
    }
};

/// Event emitted during execution
pub const ExecutionEvent = union(enum) {
    run_started: struct {
        run_id: i32,
        workflow: []const u8,
    },
    step_started: struct {
        step_id: []const u8,
        name: []const u8,
        type: plan.StepType,
    },
    step_output: struct {
        step_id: []const u8,
        line: []const u8,
    },
    llm_token: struct {
        step_id: []const u8,
        text: []const u8,
    },
    tool_call_start: struct {
        step_id: []const u8,
        tool_name: []const u8,
        tool_input: []const u8,
    },
    tool_call_end: struct {
        step_id: []const u8,
        tool_name: []const u8,
        tool_output: []const u8,
        success: bool,
    },
    agent_turn_complete: struct {
        step_id: []const u8,
        turn_number: u32,
    },
    step_completed: struct {
        step_id: []const u8,
        success: bool,
        output: ?std.json.Value,
        error_message: ?[]const u8,
    },
    run_completed: struct {
        success: bool,
        outputs: ?std.json.Value,
        error_message: ?[]const u8,
    },

    pub fn deinit(self: *ExecutionEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .run_started => |data| {
                allocator.free(data.workflow);
            },
            .step_started => |data| {
                allocator.free(data.step_id);
                allocator.free(data.name);
            },
            .step_output => |data| {
                allocator.free(data.step_id);
                allocator.free(data.line);
            },
            .llm_token => |data| {
                allocator.free(data.step_id);
                allocator.free(data.text);
            },
            .tool_call_start => |data| {
                allocator.free(data.step_id);
                allocator.free(data.tool_name);
                allocator.free(data.tool_input);
            },
            .tool_call_end => |data| {
                allocator.free(data.step_id);
                allocator.free(data.tool_name);
                allocator.free(data.tool_output);
            },
            .agent_turn_complete => |data| {
                allocator.free(data.step_id);
            },
            .step_completed => |data| {
                allocator.free(data.step_id);
                if (data.error_message) |msg| {
                    allocator.free(msg);
                }
            },
            .run_completed => |data| {
                if (data.error_message) |msg| {
                    allocator.free(msg);
                }
            },
        }
    }
};

/// Callback for streaming events
pub const EventCallback = *const fn (event: ExecutionEvent, ctx: ?*anyopaque) void;

/// Workflow executor
pub const Executor = struct {
    allocator: std.mem.Allocator,
    event_callback: ?EventCallback,
    event_ctx: ?*anyopaque,
    db_pool: ?*db.Pool,
    run_id: i32,

    pub fn init(allocator: std.mem.Allocator, db_pool: ?*db.Pool, run_id: i32) Executor {
        return .{
            .allocator = allocator,
            .event_callback = null,
            .event_ctx = null,
            .db_pool = db_pool,
            .run_id = run_id,
        };
    }

    /// Check if the workflow run has been cancelled
    fn isCancelled(self: *Executor) bool {
        if (self.db_pool) |pool| {
            const row = pool.row(
                \\SELECT status FROM workflow_runs WHERE id = $1
            , .{self.run_id}) catch return false;

            if (row) |r| {
                const status = r.get([]const u8, 0);
                return std.mem.eql(u8, status, "cancelled");
            }
        }
        return false;
    }

    pub fn setEventCallback(self: *Executor, callback: EventCallback, ctx: ?*anyopaque) void {
        self.event_callback = callback;
        self.event_ctx = ctx;
    }

    inline fn emitEvent(self: *Executor, event: ExecutionEvent) void {
        if (self.event_callback) |callback| {
            g_event_mutex.lock();
            defer g_event_mutex.unlock();
            callback(event, self.event_ctx);
        }
    }

    /// Execute a workflow plan
    pub fn execute(
        self: *Executor,
        workflow: *const plan.WorkflowDefinition,
        run_id: i32,
    ) ![]StepResult {
        // Emit run started event
        {
            const event = ExecutionEvent{
                .run_started = .{
                    .run_id = run_id,
                    .workflow = try self.allocator.dupe(u8, workflow.name),
                },
            };
            self.emitEvent(event);
        }

        // Build execution order using topological sort
        const execution_order = try self.topologicalSort(workflow);
        defer self.allocator.free(execution_order);

        // Track step results
        var results = std.ArrayList(StepResult){};
        errdefer {
            for (results.items) |*result| {
                result.deinit(self.allocator);
            }
            results.deinit(self.allocator);
        }
        defer results.deinit(self.allocator);

        var status_map = std.StringHashMap(StepStatus).init(self.allocator);
        errdefer status_map.deinit();
        defer status_map.deinit();

        var executed_steps = std.StringHashMap(void).init(self.allocator);
        errdefer executed_steps.deinit();
        defer executed_steps.deinit();

        // Execute steps using a queue with pass-based deferral so we can
        // postpone unready parallel groups without incorrectly skipping them.
        var queue = std.ArrayList(usize){};
        defer queue.deinit(self.allocator);
        try queue.appendSlice(self.allocator, execution_order);

        while (queue.items.len > 0) {
            const pass_len = queue.items.len;
            var did_work = false;
            var i: usize = 0;
            while (i < pass_len) : (i += 1) {
                const step_index = queue.orderedRemove(0);
                // Check if workflow has been cancelled
                if (self.isCancelled()) {
                    // Mark remaining steps as cancelled
                    const step = &workflow.steps[step_index];
                    if (!executed_steps.contains(step.id)) {
                        try status_map.put(step.id, .cancelled);
                        try results.append(self.allocator, .{
                            .step_id = try self.allocator.dupe(u8, step.id),
                            .status = .cancelled,
                            .exit_code = null,
                            .output = null,
                            .error_message = try self.allocator.dupe(u8, "Workflow cancelled"),
                            .turns_used = null,
                            .tokens_in = null,
                            .tokens_out = null,
                            .started_at = std.time.timestamp(),
                            .completed_at = std.time.timestamp(),
                        });
                        try executed_steps.put(step.id, {});
                    }
                    did_work = true;
                    continue;
                }

                const step = &workflow.steps[step_index];

                if (executed_steps.contains(step.id)) {
                    did_work = true;
                    continue;
                }

                // Check if dependencies succeeded
                const deps_ok = try self.checkDependencies(step, &status_map);
                if (!deps_ok) {
                    // Skip this step
                    try status_map.put(step.id, .skipped);
                    try results.append(self.allocator, .{
                        .step_id = try self.allocator.dupe(u8, step.id),
                        .status = .skipped,
                        .exit_code = null,
                        .output = null,
                        .error_message = try self.allocator.dupe(u8, "Dependency failed"),
                        .turns_used = null,
                        .tokens_in = null,
                        .tokens_out = null,
                        .started_at = std.time.timestamp(),
                        .completed_at = std.time.timestamp(),
                    });
                    try executed_steps.put(step.id, {});
                    did_work = true;
                    continue;
                }

                if (step.type == .parallel) {
                    // Ensure external deps for group branches are ready; otherwise defer
                    if (!(try parallelGroupExternalDepsReady(self, workflow, step, &status_map))) {
                        try queue.append(self.allocator, step_index);
                        continue; // no progress this iteration
                    }

                    // Wrap group execution with DB + events for parity
                    const started_at = std.time.timestamp();
                    var db_step_id: ?i32 = null;
                    if (self.db_pool) |pool| {
                        const config_str = try json.valueToString(self.allocator, step.config.data);
                        defer self.allocator.free(config_str);
                        db_step_id = try workflows_dao.createWorkflowStep(
                            pool,
                            self.run_id,
                            step.id,
                            step.name,
                            "parallel",
                            config_str,
                        );
                        try workflows_dao.updateWorkflowStepStatus(pool, db_step_id.?, "running");
                    }

                    // Emit step_started for the group
                    {
                        const event = ExecutionEvent{
                            .step_started = .{
                                .step_id = try self.allocator.dupe(u8, step.id),
                                .name = try self.allocator.dupe(u8, step.name),
                                .type = step.type,
                            },
                        };
                        self.emitEvent(event);
                    }

                    var group_failed = false;
                    const group_results = try self.executeParallelGroup(workflow, step, &status_map, &executed_steps, &group_failed);
                    for (group_results) |group_result| {
                        try results.append(self.allocator, group_result);
                    }
                    self.allocator.free(group_results);

                    // Finalize the group step itself
                    const completed_at = std.time.timestamp();
                    try status_map.put(step.id, if (group_failed) .failed else .succeeded);
                    try executed_steps.put(step.id, {});

                    // Update DB
                    if (self.db_pool) |pool| {
                        if (db_step_id) |sid| {
                            try workflows_dao.completeWorkflowStep(
                                pool,
                                sid,
                                null,
                                null,
                                if (group_failed) try self.allocator.dupe(u8, "Parallel group failed") else null,
                                null,
                                null,
                                null,
                            );
                        }
                    }

                    // Emit step_completed for the group
                    {
                        const event = ExecutionEvent{
                            .step_completed = .{
                                .step_id = try self.allocator.dupe(u8, step.id),
                                .success = !group_failed,
                                .output = null,
                                .error_message = if (group_failed) try self.allocator.dupe(u8, "Parallel group failed") else null,
                            },
                        };
                        self.emitEvent(event);
                    }

                    // Also append a StepResult row for the group itself, so summaries include it
                    try results.append(self.allocator, .{
                        .step_id = try self.allocator.dupe(u8, step.id),
                        .status = if (group_failed) .failed else .succeeded,
                        .exit_code = null,
                        .output = null,
                        .error_message = if (group_failed) try self.allocator.dupe(u8, "Parallel group failed") else null,
                        .turns_used = null,
                        .tokens_in = null,
                        .tokens_out = null,
                        .started_at = started_at,
                        .completed_at = completed_at,
                    });

                    did_work = true;
                    continue;
                }

                // Execute the step
                const result = try self.executeStep(step);
                try status_map.put(step.id, result.status);
                try executed_steps.put(step.id, {});
                try results.append(self.allocator, result);

                // If step failed and it's not a parallel group, we might want to stop
                // For now, continue execution
                did_work = true;
            }

            if (!did_work) {
                // Deadlock: none of the queued steps made progress in this pass.
                const idx = queue.orderedRemove(0);
                const step = &workflow.steps[idx];
                if (!executed_steps.contains(step.id)) {
                    try status_map.put(step.id, .failed);
                    try results.append(self.allocator, .{
                        .step_id = try self.allocator.dupe(u8, step.id),
                        .status = .failed,
                        .exit_code = null,
                        .output = null,
                        .error_message = try self.allocator.dupe(u8, "Unresolvable dependencies for step"),
                        .turns_used = null,
                        .tokens_in = null,
                        .tokens_out = null,
                        .started_at = std.time.timestamp(),
                        .completed_at = std.time.timestamp(),
                    });
                    try executed_steps.put(step.id, {});
                }
            }
        }

        // Emit run completed event
        {
            const all_succeeded = blk: {
                for (results.items) |result| {
                    if (result.status != .succeeded and result.status != .skipped) {
                        break :blk false;
                    }
                }
                break :blk true;
            };
            const event = ExecutionEvent{
                .run_completed = .{
                    .success = all_succeeded,
                    .outputs = null,
                    .error_message = if (!all_succeeded)
                        try self.allocator.dupe(u8, "One or more steps failed")
                    else
                        null,
                },
            };
            self.emitEvent(event);
        }

        return try results.toOwnedSlice(self.allocator);
    }

    /// Execute a single step
    fn executeStep(self: *Executor, step: *const plan.Step) !StepResult {
        const started_at = std.time.timestamp();

        // Create step record in database if db_pool is available
        var db_step_id: ?i32 = null;
        if (self.db_pool) |pool| {
            // Convert step config to JSON string
            const config_str = try json.valueToString(self.allocator, step.config.data);
            errdefer self.allocator.free(config_str);
            defer self.allocator.free(config_str);

            // Convert step type to string
            const step_type_str = switch (step.type) {
                .shell => "shell",
                .llm => "llm",
                .agent => "agent",
                .parallel => "parallel",
            };

            db_step_id = try workflows_dao.createWorkflowStep(
                pool,
                self.run_id,
                step.id,
                step.name,
                step_type_str,
                config_str,
            );

            // Update status to running
            try workflows_dao.updateWorkflowStepStatus(pool, db_step_id.?, "running");
        }

        // Emit step started event
        {
            const event = ExecutionEvent{
                .step_started = .{
                    .step_id = try self.allocator.dupe(u8, step.id),
                    .name = try self.allocator.dupe(u8, step.name),
                    .type = step.type,
                },
            };
            self.emitEvent(event);
        }

        // Execute based on step type
        const result = switch (step.type) {
            .shell => try self.executeShellStep(step, db_step_id),
            .parallel => try self.executeParallelStep(step),
            .llm => try self.executeLlmStep(step, db_step_id, started_at),
            .agent => try self.executeAgentStep(step, db_step_id, started_at),
        };

        // Complete step in database
        if (self.db_pool) |pool| {
            if (db_step_id) |step_db_id| {
                // Convert output to JSON string if present
                var output_str: ?[]const u8 = null;
                if (result.output) |output| {
                    output_str = try json.valueToString(self.allocator, output);
                }
                errdefer if (output_str) |s| self.allocator.free(s);
                defer if (output_str) |s| self.allocator.free(s);

                try workflows_dao.completeWorkflowStep(
                    pool,
                    step_db_id,
                    result.exit_code,
                    output_str,
                    result.error_message,
                    result.turns_used,
                    result.tokens_in,
                    result.tokens_out,
                );
            }
        }

        // Emit step completed event
        {
            const event = ExecutionEvent{
                .step_completed = .{
                    .step_id = try self.allocator.dupe(u8, step.id),
                    .success = result.status == .succeeded,
                    .output = result.output,
                    .error_message = if (result.error_message) |msg|
                        try self.allocator.dupe(u8, msg)
                    else
                        null,
                },
            };
            self.emitEvent(event);
        }

        return result;
    }

    /// Execute an LLM step (single-shot, no tools)
    fn executeLlmStep(self: *Executor, step: *const plan.Step, db_step_id: ?i32, started_at: i64) !StepResult {
        // Create LLM executor
        var llm_exec = llm_executor_mod.LlmExecutor.init(self.allocator, self.db_pool);
        var log_sequence: i32 = 0;

        // Set up event callback to forward events
        const LlmCallbackCtx = struct {
            executor: *Executor,
            step_id: []const u8,
            db_step_id: ?i32,
            log_sequence: *i32,
        };

        var callback_ctx = LlmCallbackCtx{
            .executor = self,
            .step_id = step.id,
            .db_step_id = db_step_id,
            .log_sequence = &log_sequence,
        };

        const callback = struct {
            fn cb(event: llm_executor_mod.LlmExecutionEvent, ctx: ?*anyopaque) void {
                const context: *LlmCallbackCtx = @ptrCast(@alignCast(ctx.?));
                const executor = context.executor;

                switch (event) {
                    .token => |token_data| {
                        if (context.db_step_id) |step_db_id| {
                            if (executor.db_pool) |pool| {
                                _ = workflows_dao.appendWorkflowLog(
                                    pool,
                                    step_db_id,
                                    "token",
                                    token_data.text,
                                    context.log_sequence.*,
                                ) catch {};
                                context.log_sequence.* += 1;
                            }
                        }

                        {
                            const exec_event = ExecutionEvent{
                                .llm_token = .{
                                    .step_id = executor.allocator.dupe(u8, token_data.step_id) catch return,
                                    .text = executor.allocator.dupe(u8, token_data.text) catch return,
                                },
                            };
                            executor.emitEvent(exec_event);
                        }
                    },
                    .tool_start => |tool_data| {
                        if (context.db_step_id) |step_db_id| {
                            if (executor.db_pool) |pool| {
                                const payload = buildToolLogPayload(
                                    executor.allocator,
                                    tool_data.tool_name,
                                    tool_data.tool_input,
                                    null,
                                    null,
                                ) catch return;
                                defer executor.allocator.free(payload);
                                _ = workflows_dao.appendWorkflowLog(
                                    pool,
                                    step_db_id,
                                    "tool_call",
                                    payload,
                                    context.log_sequence.*,
                                ) catch {};
                                context.log_sequence.* += 1;
                            }
                        }

                        {
                            const exec_event = ExecutionEvent{
                                .tool_call_start = .{
                                    .step_id = executor.allocator.dupe(u8, tool_data.step_id) catch return,
                                    .tool_name = executor.allocator.dupe(u8, tool_data.tool_name) catch return,
                                    .tool_input = executor.allocator.dupe(u8, tool_data.tool_input) catch return,
                                },
                            };
                            executor.emitEvent(exec_event);
                        }
                    },
                    .tool_end => |tool_data| {
                        if (context.db_step_id) |step_db_id| {
                            if (executor.db_pool) |pool| {
                                const payload = buildToolLogPayload(
                                    executor.allocator,
                                    tool_data.tool_name,
                                    null,
                                    tool_data.tool_output,
                                    tool_data.success,
                                ) catch return;
                                defer executor.allocator.free(payload);
                                _ = workflows_dao.appendWorkflowLog(
                                    pool,
                                    step_db_id,
                                    "tool_result",
                                    payload,
                                    context.log_sequence.*,
                                ) catch {};
                                context.log_sequence.* += 1;
                            }
                        }

                        {
                            const exec_event = ExecutionEvent{
                                .tool_call_end = .{
                                    .step_id = executor.allocator.dupe(u8, tool_data.step_id) catch return,
                                    .tool_name = executor.allocator.dupe(u8, tool_data.tool_name) catch return,
                                    .tool_output = executor.allocator.dupe(u8, tool_data.tool_output) catch return,
                                    .success = tool_data.success,
                                },
                            };
                            executor.emitEvent(exec_event);
                        }
                    },
                    .turn_complete => |turn_data| {
                        {
                            const exec_event = ExecutionEvent{
                                .agent_turn_complete = .{
                                    .step_id = executor.allocator.dupe(u8, turn_data.step_id) catch return,
                                    .turn_number = turn_data.turn_number,
                                },
                            };
                            executor.emitEvent(exec_event);
                        }
                    },
                }
            }
        }.cb;

        llm_exec.setEventCallback(callback, &callback_ctx);

        // Execute LLM step
        const llm_result = llm_exec.executeLlmStep(step.id, &step.config) catch |err| {
            return StepResult{
                .step_id = try self.allocator.dupe(u8, step.id),
                .status = .failed,
                .exit_code = null,
                .output = null,
                .error_message = try std.fmt.allocPrint(
                    self.allocator,
                    "LLM execution failed: {s}",
                    .{@errorName(err)},
                ),
                .turns_used = null,
                .tokens_in = null,
                .tokens_out = null,
                .started_at = started_at,
                .completed_at = std.time.timestamp(),
            };
        };

        // Record LLM usage in database if step was persisted
        if (self.db_pool) |pool| {
            if (db_step_id) |step_db_id| {
                const completed_at = std.time.timestamp();
                const latency_ms = @as(i32, @intCast(completed_at - started_at)) * 1000;

                // Get prompt name from config
                const prompt_name: ?[]const u8 = if (step.config.data.object.get("prompt_path")) |p|
                    p.string
                else
                    null;

                // Get model from config or use default
                const model = if (step.config.data.object.get("client")) |c|
                    c.string
                else
                    "claude-sonnet-4-20250514";

                // Record usage
                _ = workflows_dao.recordLlmUsage(
                    pool,
                    step_db_id,
                    prompt_name,
                    model,
                    @as(i32, @intCast(llm_result.tokens_in)),
                    @as(i32, @intCast(llm_result.tokens_out)),
                    latency_ms,
                ) catch |err| {
                    std.log.err("Failed to record LLM usage: {s}", .{@errorName(err)});
                };
            }
        }

        // Convert to StepResult
        const status: StepStatus = if (llm_result.error_message != null) .failed else .succeeded;

        return StepResult{
            .step_id = try self.allocator.dupe(u8, step.id),
            .status = status,
            .exit_code = null,
            .output = llm_result.output,
            .error_message = llm_result.error_message,
            .turns_used = @as(i32, @intCast(llm_result.turns_used)),
            .tokens_in = @as(i32, @intCast(llm_result.tokens_in)),
            .tokens_out = @as(i32, @intCast(llm_result.tokens_out)),
            .started_at = started_at,
            .completed_at = std.time.timestamp(),
        };
    }

    /// Execute an agent step (multi-turn with tools)
    fn executeAgentStep(self: *Executor, step: *const plan.Step, db_step_id: ?i32, started_at: i64) !StepResult {
        // Create LLM executor
        var llm_exec = llm_executor_mod.LlmExecutor.init(self.allocator, self.db_pool);
        var log_sequence: i32 = 0;

        // Set up event callback to forward events
        const AgentCallbackCtx = struct {
            executor: *Executor,
            step_id: []const u8,
            db_step_id: ?i32,
            log_sequence: *i32,
        };

        var callback_ctx = AgentCallbackCtx{
            .executor = self,
            .step_id = step.id,
            .db_step_id = db_step_id,
            .log_sequence = &log_sequence,
        };

        const callback = struct {
            fn cb(event: llm_executor_mod.LlmExecutionEvent, ctx: ?*anyopaque) void {
                const context: *AgentCallbackCtx = @ptrCast(@alignCast(ctx.?));
                const executor = context.executor;

                switch (event) {
                    .token => |token_data| {
                        if (context.db_step_id) |step_db_id| {
                            if (executor.db_pool) |pool| {
                                _ = workflows_dao.appendWorkflowLog(
                                    pool,
                                    step_db_id,
                                    "token",
                                    token_data.text,
                                    context.log_sequence.*,
                                ) catch {};
                                context.log_sequence.* += 1;
                            }
                        }

                        if (executor.event_callback) |exec_callback| {
                            const exec_event = ExecutionEvent{
                                .llm_token = .{
                                    .step_id = executor.allocator.dupe(u8, token_data.step_id) catch return,
                                    .text = executor.allocator.dupe(u8, token_data.text) catch return,
                                },
                            };
                            exec_callback(exec_event, executor.event_ctx);
                        }
                    },
                    .tool_start => |tool_data| {
                        if (context.db_step_id) |step_db_id| {
                            if (executor.db_pool) |pool| {
                                const payload = buildToolLogPayload(
                                    executor.allocator,
                                    tool_data.tool_name,
                                    tool_data.tool_input,
                                    null,
                                    null,
                                ) catch return;
                                defer executor.allocator.free(payload);
                                _ = workflows_dao.appendWorkflowLog(
                                    pool,
                                    step_db_id,
                                    "tool_call",
                                    payload,
                                    context.log_sequence.*,
                                ) catch {};
                                context.log_sequence.* += 1;
                            }
                        }

                        if (executor.event_callback) |exec_callback| {
                            const exec_event = ExecutionEvent{
                                .tool_call_start = .{
                                    .step_id = executor.allocator.dupe(u8, tool_data.step_id) catch return,
                                    .tool_name = executor.allocator.dupe(u8, tool_data.tool_name) catch return,
                                    .tool_input = executor.allocator.dupe(u8, tool_data.tool_input) catch return,
                                },
                            };
                            exec_callback(exec_event, executor.event_ctx);
                        }
                    },
                    .tool_end => |tool_data| {
                        if (context.db_step_id) |step_db_id| {
                            if (executor.db_pool) |pool| {
                                const payload = buildToolLogPayload(
                                    executor.allocator,
                                    tool_data.tool_name,
                                    null,
                                    tool_data.tool_output,
                                    tool_data.success,
                                ) catch return;
                                defer executor.allocator.free(payload);
                                _ = workflows_dao.appendWorkflowLog(
                                    pool,
                                    step_db_id,
                                    "tool_result",
                                    payload,
                                    context.log_sequence.*,
                                ) catch {};
                                context.log_sequence.* += 1;
                            }
                        }

                        if (executor.event_callback) |exec_callback| {
                            const exec_event = ExecutionEvent{
                                .tool_call_end = .{
                                    .step_id = executor.allocator.dupe(u8, tool_data.step_id) catch return,
                                    .tool_name = executor.allocator.dupe(u8, tool_data.tool_name) catch return,
                                    .tool_output = executor.allocator.dupe(u8, tool_data.tool_output) catch return,
                                    .success = tool_data.success,
                                },
                            };
                            exec_callback(exec_event, executor.event_ctx);
                        }
                    },
                    .turn_complete => |turn_data| {
                        if (executor.event_callback) |exec_callback| {
                            const exec_event = ExecutionEvent{
                                .agent_turn_complete = .{
                                    .step_id = executor.allocator.dupe(u8, turn_data.step_id) catch return,
                                    .turn_number = turn_data.turn_number,
                                },
                            };
                            exec_callback(exec_event, executor.event_ctx);
                        }
                    },
                }
            }
        }.cb;

        llm_exec.setEventCallback(callback, &callback_ctx);

        // Execute agent step
        const agent_result = llm_exec.executeAgentStep(step.id, &step.config) catch |err| {
            return StepResult{
                .step_id = try self.allocator.dupe(u8, step.id),
                .status = .failed,
                .exit_code = null,
                .output = null,
                .error_message = try std.fmt.allocPrint(
                    self.allocator,
                    "Agent execution failed: {s}",
                    .{@errorName(err)},
                ),
                .turns_used = null,
                .tokens_in = null,
                .tokens_out = null,
                .started_at = started_at,
                .completed_at = std.time.timestamp(),
            };
        };

        // Record LLM usage in database if step was persisted
        if (self.db_pool) |pool| {
            if (db_step_id) |step_db_id| {
                const completed_at = std.time.timestamp();
                const latency_ms = @as(i32, @intCast(completed_at - started_at)) * 1000;

                // Get prompt name from config
                const prompt_name: ?[]const u8 = if (step.config.data.object.get("prompt_path")) |p|
                    p.string
                else
                    null;

                // Get model from config or use default
                const model = if (step.config.data.object.get("client")) |c|
                    c.string
                else
                    "claude-sonnet-4-20250514";

                // Record usage
                _ = workflows_dao.recordLlmUsage(
                    pool,
                    step_db_id,
                    prompt_name,
                    model,
                    @as(i32, @intCast(agent_result.tokens_in)),
                    @as(i32, @intCast(agent_result.tokens_out)),
                    latency_ms,
                ) catch |err| {
                    std.log.err("Failed to record agent LLM usage: {s}", .{@errorName(err)});
                };
            }
        }

        // Convert to StepResult
        const status: StepStatus = if (agent_result.error_message != null) .failed else .succeeded;

        return StepResult{
            .step_id = try self.allocator.dupe(u8, step.id),
            .status = status,
            .exit_code = null,
            .output = agent_result.output,
            .error_message = agent_result.error_message,
            .turns_used = @as(i32, @intCast(agent_result.turns_used)),
            .tokens_in = @as(i32, @intCast(agent_result.tokens_in)),
            .tokens_out = @as(i32, @intCast(agent_result.tokens_out)),
            .started_at = started_at,
            .completed_at = std.time.timestamp(),
        };
    }

    /// Execute a shell step
    fn executeShellStep(self: *Executor, step: *const plan.Step, db_step_id: ?i32) !StepResult {
        const started_at = std.time.timestamp();
        var log_sequence: i32 = 0;

        // Extract command from config
        const config = step.config.data;
        const cmd = switch (config) {
            .object => |obj| blk: {
                const cmd_value = obj.get("cmd") orelse {
                    return StepResult{
                        .step_id = try self.allocator.dupe(u8, step.id),
                        .status = .failed,
                        .exit_code = null,
                        .output = null,
                        .error_message = try self.allocator.dupe(u8, "Missing 'cmd' in shell step config"),
                        .turns_used = null,
                        .tokens_in = null,
                        .tokens_out = null,
                        .started_at = started_at,
                        .completed_at = std.time.timestamp(),
                    };
                };
                break :blk switch (cmd_value) {
                    .string => |s| s,
                    else => {
                        return StepResult{
                            .step_id = try self.allocator.dupe(u8, step.id),
                            .status = .failed,
                            .exit_code = null,
                            .output = null,
                            .error_message = try self.allocator.dupe(u8, "'cmd' must be a string"),
                            .turns_used = null,
                            .tokens_in = null,
                            .tokens_out = null,
                            .started_at = started_at,
                            .completed_at = std.time.timestamp(),
                        };
                    },
                };
            },
            else => {
                return StepResult{
                    .step_id = try self.allocator.dupe(u8, step.id),
                    .status = .failed,
                    .exit_code = null,
                    .output = null,
                    .error_message = try self.allocator.dupe(u8, "Shell step config must be an object"),
                    .turns_used = null,
                    .tokens_in = null,
                    .tokens_out = null,
                    .started_at = started_at,
                    .completed_at = std.time.timestamp(),
                };
            },
        };

        // Extract environment variables if present
        var env_map = std.process.EnvMap.init(self.allocator);
        errdefer env_map.deinit();
        defer env_map.deinit();

        // Copy current environment
        var current_env = try std.process.getEnvMap(self.allocator);
        errdefer current_env.deinit();
        defer current_env.deinit();
        var env_it = current_env.iterator();
        while (env_it.next()) |entry| {
            try env_map.put(entry.key_ptr.*, entry.value_ptr.*);
        }

        // Add step-specific env vars
        if (config == .object) {
            if (config.object.get("env")) |env_value| {
                if (env_value == .object) {
                    var it = env_value.object.iterator();
                    while (it.next()) |entry| {
                        const value_str = switch (entry.value_ptr.*) {
                            .string => |s| s,
                            else => continue,
                        };
                        try env_map.put(entry.key_ptr.*, value_str);
                    }
                }
            }
        }

        // WARNING: Commands come from workflow YAML. Do not include untrusted user input in cmd.
        // For complex shell features, workflows should use a dedicated shell step type.
        // TODO: Add a "trusted" shell step type that allows `sh -c` for advanced use cases.
        //
        // Parse command into argv array for safer execution without shell interpretation
        // This prevents command injection if untrusted data somehow flows into cmd.
        var argv_list = std.ArrayList([]const u8){};
        errdefer argv_list.deinit(self.allocator);
        defer argv_list.deinit(self.allocator);

        // Simple whitespace tokenization (doesn't handle quotes/escapes)
        // This is intentionally limited to prevent shell metacharacter interpretation
        var iter = std.mem.tokenizeAny(u8, cmd, " \t\n\r");
        while (iter.next()) |token| {
            try argv_list.append(self.allocator, token);
        }

        if (argv_list.items.len == 0) {
            return StepResult{
                .step_id = try self.allocator.dupe(u8, step.id),
                .status = .failed,
                .exit_code = null,
                .output = null,
                .error_message = try self.allocator.dupe(u8, "Empty command"),
                .turns_used = null,
                .tokens_in = null,
                .tokens_out = null,
                .started_at = started_at,
                .completed_at = std.time.timestamp(),
            };
        }

        // Use direct argv execution instead of sh -c to avoid shell injection

        var child = std.process.Child.init(argv_list.items, self.allocator);
        child.env_map = &env_map;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch |err| {
            return StepResult{
                .step_id = try self.allocator.dupe(u8, step.id),
                .status = .failed,
                .exit_code = null,
                .output = null,
                .error_message = try std.fmt.allocPrint(
                    self.allocator,
                    "Failed to spawn command: {s}",
                    .{@errorName(err)},
                ),
                .turns_used = null,
                .tokens_in = null,
                .tokens_out = null,
                .started_at = started_at,
                .completed_at = std.time.timestamp(),
            };
        };

        var stdout_acc = std.ArrayList(u8){};
        errdefer stdout_acc.deinit(self.allocator);
        defer stdout_acc.deinit(self.allocator);
        var stderr_acc = std.ArrayList(u8){};
        errdefer stderr_acc.deinit(self.allocator);
        defer stderr_acc.deinit(self.allocator);

        var stdout_open = true;
        var stderr_open = true;

        var poll_fds = [_]std.posix.pollfd{
            .{ .fd = child.stdout.?.handle, .events = std.posix.POLL.IN, .revents = 0 },
            .{ .fd = child.stderr.?.handle, .events = std.posix.POLL.IN, .revents = 0 },
        };

        var stdout_buf: [4096]u8 = undefined;
        var stderr_buf: [4096]u8 = undefined;

        while (stdout_open or stderr_open) {
            // Check for cancellation
            if (self.isCancelled()) {
                _ = child.kill() catch {};
                return StepResult{
                    .step_id = try self.allocator.dupe(u8, step.id),
                    .status = .cancelled,
                    .exit_code = null,
                    .output = null,
                    .error_message = try self.allocator.dupe(u8, "Workflow cancelled"),
                    .turns_used = null,
                    .tokens_in = null,
                    .tokens_out = null,
                    .started_at = started_at,
                    .completed_at = std.time.timestamp(),
                };
            }

            _ = try std.posix.poll(&poll_fds, -1);

            if (stdout_open and poll_fds[0].revents != 0) {
                const bytes_read = child.stdout.?.read(&stdout_buf) catch |err| {
                    _ = child.kill() catch {};
                    return StepResult{
                        .step_id = try self.allocator.dupe(u8, step.id),
                        .status = .failed,
                        .exit_code = null,
                        .output = null,
                        .error_message = try std.fmt.allocPrint(
                            self.allocator,
                            "Failed to read stdout: {s}",
                            .{@errorName(err)},
                        ),
                        .turns_used = null,
                        .tokens_in = null,
                        .tokens_out = null,
                        .started_at = started_at,
                        .completed_at = std.time.timestamp(),
                    };
                };

                if (bytes_read == 0) {
                    stdout_open = false;
                    poll_fds[0].fd = -1;
                } else {
                    const chunk = stdout_buf[0..bytes_read];
                    try stdout_acc.appendSlice(self.allocator, chunk);

                    if (self.db_pool) |pool| {
                        if (db_step_id) |step_db_id| {
                            _ = try workflows_dao.appendWorkflowLog(
                                pool,
                                step_db_id,
                                "stdout",
                                chunk,
                                log_sequence,
                            );
                            log_sequence += 1;
                        }
                    }

                    if (self.event_callback) |callback| {
                        const event = ExecutionEvent{
                            .step_output = .{
                                .step_id = try self.allocator.dupe(u8, step.id),
                                .line = try self.allocator.dupe(u8, chunk),
                            },
                        };
                        callback(event, self.event_ctx);
                    }
                }
            }

            if (stderr_open and poll_fds[1].revents != 0) {
                const bytes_read = child.stderr.?.read(&stderr_buf) catch |err| {
                    _ = child.kill() catch {};
                    return StepResult{
                        .step_id = try self.allocator.dupe(u8, step.id),
                        .status = .failed,
                        .exit_code = null,
                        .output = null,
                        .error_message = try std.fmt.allocPrint(
                            self.allocator,
                            "Failed to read stderr: {s}",
                            .{@errorName(err)},
                        ),
                        .turns_used = null,
                        .tokens_in = null,
                        .tokens_out = null,
                        .started_at = started_at,
                        .completed_at = std.time.timestamp(),
                    };
                };

                if (bytes_read == 0) {
                    stderr_open = false;
                    poll_fds[1].fd = -1;
                } else {
                    const chunk = stderr_buf[0..bytes_read];
                    try stderr_acc.appendSlice(self.allocator, chunk);

                    if (self.db_pool) |pool| {
                        if (db_step_id) |step_db_id| {
                            _ = try workflows_dao.appendWorkflowLog(
                                pool,
                                step_db_id,
                                "stderr",
                                chunk,
                                log_sequence,
                            );
                            log_sequence += 1;
                        }
                    }

                    if (self.event_callback) |callback| {
                        const event = ExecutionEvent{
                            .step_output = .{
                                .step_id = try self.allocator.dupe(u8, step.id),
                                .line = try self.allocator.dupe(u8, chunk),
                            },
                        };
                        callback(event, self.event_ctx);
                    }
                }
            }
        }

        // Wait for completion
        const term = child.wait() catch |err| {
            return StepResult{
                .step_id = try self.allocator.dupe(u8, step.id),
                .status = .failed,
                .exit_code = null,
                .output = null,
                .error_message = try std.fmt.allocPrint(
                    self.allocator,
                    "Failed to wait for command: {s}",
                    .{@errorName(err)},
                ),
                .turns_used = null,
                .tokens_in = null,
                .tokens_out = null,
                .started_at = started_at,
                .completed_at = std.time.timestamp(),
            };
        };

        // Build output JSON
        var output_obj = std.json.ObjectMap.init(self.allocator);
        // Duplicate strings since stdout/stderr will be freed by defer
        try output_obj.put("stdout", .{ .string = try self.allocator.dupe(u8, stdout_acc.items) });
        try output_obj.put("stderr", .{ .string = try self.allocator.dupe(u8, stderr_acc.items) });

        const exit_code: i32 = switch (term) {
            .Exited => |code| @intCast(code),
            .Signal => -1,
            .Stopped => -1,
            .Unknown => -1,
        };

        const success = exit_code == 0;
        const error_message = if (!success and stderr_acc.items.len > 0)
            try self.allocator.dupe(u8, stderr_acc.items)
        else
            null;

        return StepResult{
            .step_id = try self.allocator.dupe(u8, step.id),
            .status = if (success) .succeeded else .failed,
            .exit_code = exit_code,
            .output = .{ .object = output_obj },
            .error_message = error_message,
            .turns_used = null,
            .tokens_in = null,
            .tokens_out = null,
            .started_at = started_at,
            .completed_at = std.time.timestamp(),
        };
    }

    /// Execute a parallel step placeholder (should be orchestrated at group level).
    ///
    /// Note: Parallel execution is handled by `executeParallelGroup`, which has
    /// access to the full workflow and dependency state. This function returns a
    /// failed result to prevent false positives if called directly.
    fn executeParallelStep(self: *Executor, step: *const plan.Step) !StepResult {
        _ = self;
        return StepResult{
            .step_id = try self.allocator.dupe(u8, step.id),
            .status = .failed,
            .exit_code = null,
            .output = null,
            .error_message = try self.allocator.dupe(u8, "Parallel steps must be executed as a group"),
            .turns_used = null,
            .tokens_in = null,
            .tokens_out = null,
            .started_at = std.time.timestamp(),
            .completed_at = std.time.timestamp(),
        };
    }

    fn executeParallelGroup(
        self: *Executor,
        workflow: *const plan.WorkflowDefinition,
        parallel_step: *const plan.Step,
        status_map: *std.StringHashMap(StepStatus),
        executed_steps: *std.StringHashMap(void),
        out_group_failed: *bool,
    ) ![]StepResult {
        var results = std.ArrayList(StepResult){};
        errdefer {
            for (results.items) |*result| {
                result.deinit(self.allocator);
            }
            results.deinit(self.allocator);
        }

        const config = parallel_step.config.data;
        const step_ids_value = if (config == .object) config.object.get("step_ids") else null;
        if (step_ids_value == null or step_ids_value.? != .array) {
            try results.append(self.allocator, .{
                .step_id = try self.allocator.dupe(u8, parallel_step.id),
                .status = .failed,
                .exit_code = null,
                .output = null,
                .error_message = try self.allocator.dupe(u8, "Parallel step missing step_ids"),
                .turns_used = null,
                .tokens_in = null,
                .tokens_out = null,
                .started_at = std.time.timestamp(),
                .completed_at = std.time.timestamp(),
            });
            try status_map.put(parallel_step.id, .failed);
            try executed_steps.put(parallel_step.id, {});
            return try results.toOwnedSlice(self.allocator);
        }

        var step_lookup = std.StringHashMap(*const plan.Step).init(self.allocator);
        errdefer step_lookup.deinit();
        defer step_lookup.deinit();
        for (workflow.steps) |*step| {
            _ = step_lookup.put(step.id, step) catch {};
        }
        // Build subgraph of the group's step_ids
        var sub_nodes = std.ArrayList(*const plan.Step){};
        errdefer sub_nodes.deinit(self.allocator);
        defer sub_nodes.deinit(self.allocator);
        for (step_ids_value.?.array.items) |item| {
            if (item != .string) continue;
            if (step_lookup.get(item.string)) |s| {
                try sub_nodes.append(self.allocator, s);
            } else {
                // Unknown step id → emit failure
                try results.append(self.allocator, .{
                    .step_id = try self.allocator.dupe(u8, item.string),
                    .status = .failed,
                    .exit_code = null,
                    .output = null,
                    .error_message = try self.allocator.dupe(u8, "Unknown step_id in parallel group"),
                    .turns_used = null,
                    .tokens_in = null,
                    .tokens_out = null,
                    .started_at = std.time.timestamp(),
                    .completed_at = std.time.timestamp(),
                });
                any_failed = true;
            }
        }

        // Map for quick membership checks
        var in_group = std.StringHashMap(bool).init(self.allocator);
        errdefer in_group.deinit();
        defer in_group.deinit();
        for (sub_nodes.items) |s| {
            try in_group.put(s.id, true);
        }

        // Concurrency limit
        var max_concurrency: usize = 4; // default bound
        if (parallel_step.config.data == .object) {
            if (parallel_step.config.data.object.get("max_concurrency")) |mc| {
                if (mc == .integer and mc.integer > 0) max_concurrency = @intCast(mc.integer);
            }
        }

        // Failure policy: "all" (default) or "fail_fast"
        var fail_fast: bool = false;
        if (parallel_step.config.data == .object) {
            if (parallel_step.config.data.object.get("failure_mode")) |fm| {
                if (fm == .string and std.mem.eql(u8, fm.string, "fail_fast")) fail_fast = true;
            }
        }

        // Layered scheduling within the group
        var remaining = std.AutoHashMap([]const u8, *const plan.Step).init(self.allocator);
        errdefer remaining.deinit();
        defer remaining.deinit();
        var any_failed = false;
        for (sub_nodes.items) |s| {
            if (executed_steps.contains(s.id)) {
                // Already executed earlier in the global loop. Respect its status.
                const st = status_map.get(s.id) orelse .pending;
                if (!(st == .succeeded or st == .skipped)) any_failed = true;
                continue;
            }
            try remaining.put(s.id, s);
        }

        const group_started_at = std.time.timestamp();

        while (remaining.count() > 0) {
            // Build ready set for this layer
            var ready = std.ArrayList(*const plan.Step){};
            defer ready.deinit(self.allocator);

            var it = remaining.iterator();
            while (it.next()) |entry| {
                const s = entry.value_ptr.*;
                var ok = true;
                for (s.depends_on) |dep_id| {
                    if (in_group.contains(dep_id)) {
                        // Intra-group dep must be completed successfully already
                        const st = status_map.get(dep_id) orelse .pending;
                        if (st != .succeeded) {
                            ok = false;
                            break;
                        }
                    } else {
                        // External dep must be succeeded in global map
                        const st = status_map.get(dep_id) orelse .pending;
                        if (st != .succeeded) {
                            ok = false;
                            break;
                        }
                    }
                }
                if (ok) try ready.append(self.allocator, s);
            }

            if (ready.items.len == 0) {
                // Cycle or blocked on missing deps → fail remaining nodes
                var it2 = remaining.iterator();
                while (it2.next()) |entry2| {
                    const s = entry2.value_ptr.*;
                    try status_map.put(s.id, .failed);
                    try executed_steps.put(s.id, {});
                    try results.append(self.allocator, .{
                        .step_id = try self.allocator.dupe(u8, s.id),
                        .status = .failed,
                        .exit_code = null,
                        .output = null,
                        .error_message = try self.allocator.dupe(u8, "No ready branches in parallel group (cycle or unmet deps)"),
                        .turns_used = null,
                        .tokens_in = null,
                        .tokens_out = null,
                        .started_at = std.time.timestamp(),
                        .completed_at = std.time.timestamp(),
                    });
                }
                any_failed = true;
                break;
            }

            // Handle nested parallel groups first (synchronously)
            var ready_non = std.ArrayList(*const plan.Step){};
            defer ready_non.deinit(self.allocator);
            for (ready.items) |s_ready| {
                if (s_ready.type == .parallel) {
                    // DB + events for nested group
                    var db_step_id: ?i32 = null;
                    if (self.db_pool) |pool| {
                        const cfg = try json.valueToString(self.allocator, s_ready.config.data);
                        defer self.allocator.free(cfg);
                        db_step_id = try workflows_dao.createWorkflowStep(
                            pool,
                            self.run_id,
                            s_ready.id,
                            s_ready.name,
                            "parallel",
                            cfg,
                        );
                        try workflows_dao.updateWorkflowStepStatus(pool, db_step_id.?, "running");
                    }
                    // Emit step_started
                    {
                        const ev = ExecutionEvent{ .step_started = .{
                            .step_id = try self.allocator.dupe(u8, s_ready.id),
                            .name = try self.allocator.dupe(u8, s_ready.name),
                            .type = s_ready.type,
                        } };
                        self.emitEvent(ev);
                    }

                    var nested_failed = false;
                    const nested_results = try self.executeParallelGroup(workflow, s_ready, status_map, executed_steps, &nested_failed);
                    for (nested_results) |nr| try results.append(self.allocator, nr);
                    self.allocator.free(nested_results);

                    try status_map.put(s_ready.id, if (nested_failed) .failed else .succeeded);
                    try executed_steps.put(s_ready.id, {});

                    // Finalize DB and emit completed
                    if (self.db_pool) |pool| {
                        if (db_step_id) |sid| {
                            try workflows_dao.completeWorkflowStep(
                                pool,
                                sid,
                                null,
                                null,
                                if (nested_failed) try self.allocator.dupe(u8, "Parallel group failed") else null,
                                null,
                                null,
                                null,
                            );
                        }
                    }
                    {
                        const evc = ExecutionEvent{ .step_completed = .{
                            .step_id = try self.allocator.dupe(u8, s_ready.id),
                            .success = !nested_failed,
                            .output = null,
                            .error_message = if (nested_failed) try self.allocator.dupe(u8, "Parallel group failed") else null,
                        } };
                        self.emitEvent(evc);
                    }

                    if (nested_failed) any_failed = true;
                    _ = remaining.remove(s_ready.id);
                } else {
                    try ready_non.append(self.allocator, s_ready);
                }
            }

            // Run this layer with bounded concurrency
            var index: usize = 0;
            while (index < ready_non.items.len) {
                const batch = @min(max_concurrency, ready_non.items.len - index);
                var workers = try self.allocator.alloc(ParallelWorker, batch);
                defer self.allocator.free(workers);
                var threads = try self.allocator.alloc(std.Thread, batch);
                defer self.allocator.free(threads);

                var spawned: usize = 0;
                var spawn_err: ?anyerror = null;
                // Spawn
                var j: usize = 0;
                while (j < batch) : (j += 1) {
                    const sp = ready_non.items[index + j];
                    workers[j] = .{
                        .step = sp,
                        .allocator = self.allocator,
                        .event_callback = self.event_callback,
                        .event_ctx = self.event_ctx,
                    };
                    const t = std.Thread.spawn(.{}, parallelWorkerMain, .{ &workers[j], self.db_pool, self.run_id }) catch |e| {
                        spawn_err = e;
                        break;
                    };
                    threads[j] = t;
                    spawned += 1;
                }

                // If spawn failed, join already started threads, then fail remaining
                if (spawn_err) |_| {
                    for (threads[0..spawned]) |th| th.join();
                    // Mark the one that failed to spawn
                    const sp = ready_non.items[index + spawned];
                    try status_map.put(sp.id, .failed);
                    try executed_steps.put(sp.id, {});
                    try results.append(self.allocator, .{
                        .step_id = try self.allocator.dupe(u8, sp.id),
                        .status = .failed,
                        .exit_code = null,
                        .output = null,
                        .error_message = try self.allocator.dupe(u8, "Thread spawn failed in parallel group"),
                        .turns_used = null,
                        .tokens_in = null,
                        .tokens_out = null,
                        .started_at = std.time.timestamp(),
                        .completed_at = std.time.timestamp(),
                    });
                    any_failed = true;
                    // Remove spawned + failed-from-spawn from remaining
                    var k: usize = 0;
                    while (k < spawned + 1) : (k += 1) {
                        const rm = ready_non.items[index + k];
                        _ = remaining.remove(rm.id);
                    }
                    if (fail_fast) {
                        // Best-effort: do not launch more; cancel rest as skipped
                        var it3 = remaining.iterator();
                        while (it3.next()) |e2| {
                            const s2 = e2.value_ptr.*;
                            try status_map.put(s2.id, .cancelled);
                            try executed_steps.put(s2.id, {});
                            try results.append(self.allocator, .{
                                .step_id = try self.allocator.dupe(u8, s2.id),
                                .status = .cancelled,
                                .exit_code = null,
                                .output = null,
                                .error_message = try self.allocator.dupe(u8, "Cancelled due to fail_fast"),
                                .turns_used = null,
                                .tokens_in = null,
                                .tokens_out = null,
                                .started_at = std.time.timestamp(),
                                .completed_at = std.time.timestamp(),
                            });
                        }
                        remaining.clearAndFree();
                        break;
                    }
                    index += spawned + 1;
                    continue;
                }

                // Join and collect
                for (threads[0..spawned]) |th| th.join();
                var jj: usize = 0;
                while (jj < spawned) : (jj += 1) {
                    const w = workers[jj];
                    _ = remaining.remove(w.step.id);
                    try status_map.put(w.step.id, w.status);
                    try executed_steps.put(w.step.id, {});

                    // Re-hydrate JSON output from worker's c-allocated buffer
                    var out_val: ?std.json.Value = null;
                    if (w.output_json_c) |sbytes| {
                        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, sbytes, .{}) catch null;
                        if (parsed) |p| {
                            out_val = p.value;
                            // p.deinit would free self.allocator memory; but we want ownership → no deinit here
                        }
                        std.heap.c_allocator.free(sbytes);
                    }
                    const err_msg = blk: {
                        if (w.error_message_c) |em| {
                            const d = try self.allocator.dupe(u8, em);
                            std.heap.c_allocator.free(em);
                            break :blk d;
                        }
                        break :blk null;
                    };

                    try results.append(self.allocator, .{
                        .step_id = try self.allocator.dupe(u8, w.step.id),
                        .status = w.status,
                        .exit_code = w.exit_code,
                        .output = out_val,
                        .error_message = err_msg,
                        .turns_used = w.turns_used,
                        .tokens_in = w.tokens_in,
                        .tokens_out = w.tokens_out,
                        .started_at = w.started_at,
                        .completed_at = w.completed_at,
                    });

                    if (w.status == .failed) any_failed = true;
                }

                if (fail_fast and any_failed) {
                    // Cancel all remaining nodes in group
                    var it4 = remaining.iterator();
                    while (it4.next()) |er| {
                        const s3 = er.value_ptr.*;
                        try status_map.put(s3.id, .cancelled);
                        try executed_steps.put(s3.id, {});
                        try results.append(self.allocator, .{
                            .step_id = try self.allocator.dupe(u8, s3.id),
                            .status = .cancelled,
                            .exit_code = null,
                            .output = null,
                            .error_message = try self.allocator.dupe(u8, "Cancelled due to fail_fast"),
                            .turns_used = null,
                            .tokens_in = null,
                            .tokens_out = null,
                            .started_at = std.time.timestamp(),
                            .completed_at = std.time.timestamp(),
                        });
                    }
                    remaining.clearAndFree();
                    break;
                }

                index += spawned;
            }
        }

        out_group_failed.* = any_failed;
        return try results.toOwnedSlice(self.allocator);
    }

    /// Check if all dependencies of a step have succeeded
    fn checkDependencies(
        self: *Executor,
        step: *const plan.Step,
        status_map: *std.StringHashMap(StepStatus),
    ) !bool {
        _ = self;
        for (step.depends_on) |dep_id| {
            const status = status_map.get(dep_id) orelse return false;
            if (status != .succeeded) {
                return false;
            }
        }
        return true;
    }

    /// Perform topological sort on workflow steps
    /// Returns array of step indices in execution order
    fn topologicalSort(self: *Executor, workflow: *const plan.WorkflowDefinition) ![]usize {
        const n = workflow.steps.len;
        if (n == 0) return try self.allocator.alloc(usize, 0);

        // Build adjacency list and in-degree count
        var adj_list = try self.allocator.alloc(std.ArrayList(usize), n);
        defer {
            for (adj_list) |*list| {
                list.deinit(self.allocator);
            }
            self.allocator.free(adj_list);
        }

        var in_degree = try self.allocator.alloc(usize, n);
        defer self.allocator.free(in_degree);

        // Initialize
        for (0..n) |i| {
            adj_list[i] = std.ArrayList(usize){};
            in_degree[i] = 0;
        }

        // Build step ID to index map
        var id_to_index = std.StringHashMap(usize).init(self.allocator);
        errdefer id_to_index.deinit();
        defer id_to_index.deinit();
        for (workflow.steps, 0..) |step, i| {
            try id_to_index.put(step.id, i);
        }

        // Build graph
        for (workflow.steps, 0..) |step, i| {
            for (step.depends_on) |dep_id| {
                const dep_index = id_to_index.get(dep_id) orelse continue;
                try adj_list[dep_index].append(self.allocator, i);
                in_degree[i] += 1;
            }
        }

        // Kahn's algorithm for topological sort
        var queue = std.ArrayList(usize){};
        errdefer queue.deinit(self.allocator);
        defer queue.deinit(self.allocator);

        // Add all nodes with in-degree 0
        for (in_degree, 0..) |degree, i| {
            if (degree == 0) {
                try queue.append(self.allocator, i);
            }
        }

        var result = std.ArrayList(usize){};
        errdefer result.deinit(self.allocator);

        while (queue.items.len > 0) {
            const u = queue.orderedRemove(0);
            try result.append(self.allocator, u);

            // Reduce in-degree of neighbors
            for (adj_list[u].items) |v| {
                in_degree[v] -= 1;
                if (in_degree[v] == 0) {
                    try queue.append(self.allocator, v);
                }
            }
        }

        // Check if all nodes were processed (no cycles)
        if (result.items.len != n) {
            return error.CycleDetected;
        }

        return try result.toOwnedSlice(self.allocator);
    }
};

// Helper: determine if a parallel group's external dependencies are satisfied.
fn parallelGroupExternalDepsReady(
    self: *Executor,
    workflow: *const plan.WorkflowDefinition,
    group_step: *const plan.Step,
    status_map: *std.StringHashMap(StepStatus),
) !bool {
    _ = workflow; // currently unused; may need if we alter parsing
    // If the parser leaves group.depends_on empty, we compute readiness by checking
    // all external deps of members: if any member depends_on outside the group and
    // it is not succeeded yet, we should defer the group execution.
    const config = group_step.config.data;
    const step_ids_value = if (config == .object) config.object.get("step_ids") else null;
    if (step_ids_value == null or step_ids_value.? != .array) return false;

    // Collect group membership for quick checks
    var in_group = std.StringHashMap(bool).init(self.allocator);
    defer in_group.deinit();
    for (step_ids_value.?.array.items) |item| {
        if (item == .string) {
            _ = try in_group.put(item.string, true);
        }
    }

    // For each member, ensure all external deps are succeeded
    for (step_ids_value.?.array.items) |item| {
        if (item != .string) continue;
        const sid = item.string;
        // Find the step in the workflow
        var found: ?*const plan.Step = null;
        for (workflow.steps) |*s| {
            if (std.mem.eql(u8, s.id, sid)) {
                found = s;
                break;
            }
        }
        if (found == null) continue;
        const st = found.?;
        for (st.depends_on) |dep_id| {
            if (!in_group.contains(dep_id)) {
                const ds = status_map.get(dep_id) orelse return false;
                if (ds != .succeeded) return false;
            }
        }
    }
    return true;
}

// Tests
test "topological sort - linear dependencies" {
    const allocator = std.testing.allocator;

    var executor = Executor.init(allocator, null, 1);

    // Create workflow: step1 -> step2 -> step3
    // Allocate empty depends_on array on heap for step1
    const step1_deps = try allocator.alloc([]const u8, 0);
    var step1 = plan.Step{
        .id = try allocator.dupe(u8, "step1"),
        .name = try allocator.dupe(u8, "Step 1"),
        .type = .shell,
        .config = .{ .data = .null },
        .depends_on = step1_deps,
    };
    defer step1.deinit(allocator);

    // Allocate depends_on array on heap for step2
    const step2_deps = try allocator.alloc([]const u8, 1);
    step2_deps[0] = try allocator.dupe(u8, "step1");
    var step2 = plan.Step{
        .id = try allocator.dupe(u8, "step2"),
        .name = try allocator.dupe(u8, "Step 2"),
        .type = .shell,
        .config = .{ .data = .null },
        .depends_on = step2_deps,
    };
    defer {
        step2.deinit(allocator);
    }

    // Allocate depends_on array on heap for step3
    const step3_deps = try allocator.alloc([]const u8, 1);
    step3_deps[0] = try allocator.dupe(u8, "step2");
    var step3 = plan.Step{
        .id = try allocator.dupe(u8, "step3"),
        .name = try allocator.dupe(u8, "Step 3"),
        .type = .shell,
        .config = .{ .data = .null },
        .depends_on = step3_deps,
    };
    defer {
        step3.deinit(allocator);
    }

    var steps = [_]plan.Step{ step1, step2, step3 };
    const workflow = plan.WorkflowDefinition{
        .name = "test",
        .triggers = @constCast(&[_]plan.Trigger{}),
        .image = null,
        .dockerfile = null,
        .steps = &steps,
    };

    const order = try executor.topologicalSort(&workflow);
    defer allocator.free(order);

    try std.testing.expectEqual(@as(usize, 3), order.len);
    try std.testing.expectEqual(@as(usize, 0), order[0]); // step1
    try std.testing.expectEqual(@as(usize, 1), order[1]); // step2
    try std.testing.expectEqual(@as(usize, 2), order[2]); // step3
}

test "topological sort - parallel steps" {
    const allocator = std.testing.allocator;

    var executor = Executor.init(allocator, null, 1);

    // Create workflow: step1 -> (step2, step3) -> step4
    // Allocate empty depends_on array on heap for step1
    const step1_deps = try allocator.alloc([]const u8, 0);
    var step1 = plan.Step{
        .id = try allocator.dupe(u8, "step1"),
        .name = try allocator.dupe(u8, "Step 1"),
        .type = .shell,
        .config = .{ .data = .null },
        .depends_on = step1_deps,
    };
    defer step1.deinit(allocator);

    // Allocate depends_on array on heap for step2
    const step2_deps = try allocator.alloc([]const u8, 1);
    step2_deps[0] = try allocator.dupe(u8, "step1");
    var step2 = plan.Step{
        .id = try allocator.dupe(u8, "step2"),
        .name = try allocator.dupe(u8, "Step 2"),
        .type = .shell,
        .config = .{ .data = .null },
        .depends_on = step2_deps,
    };
    defer {
        step2.deinit(allocator);
    }

    // Allocate depends_on array on heap for step3
    const step3_deps = try allocator.alloc([]const u8, 1);
    step3_deps[0] = try allocator.dupe(u8, "step1");
    var step3 = plan.Step{
        .id = try allocator.dupe(u8, "step3"),
        .name = try allocator.dupe(u8, "Step 3"),
        .type = .shell,
        .config = .{ .data = .null },
        .depends_on = step3_deps,
    };
    defer {
        step3.deinit(allocator);
    }

    // Allocate depends_on array on heap for step4
    const step4_deps = try allocator.alloc([]const u8, 2);
    step4_deps[0] = try allocator.dupe(u8, "step2");
    step4_deps[1] = try allocator.dupe(u8, "step3");
    var step4 = plan.Step{
        .id = try allocator.dupe(u8, "step4"),
        .name = try allocator.dupe(u8, "Step 4"),
        .type = .shell,
        .config = .{ .data = .null },
        .depends_on = step4_deps,
    };
    defer step4.deinit(allocator);

    var steps = [_]plan.Step{ step1, step2, step3, step4 };
    const workflow = plan.WorkflowDefinition{
        .name = "test",
        .triggers = @constCast(&[_]plan.Trigger{}),
        .image = null,
        .dockerfile = null,
        .steps = &steps,
    };

    const order = try executor.topologicalSort(&workflow);
    defer allocator.free(order);

    try std.testing.expectEqual(@as(usize, 4), order.len);
    try std.testing.expectEqual(@as(usize, 0), order[0]); // step1 first
    // step2 and step3 can be in any order
    try std.testing.expectEqual(@as(usize, 3), order[3]); // step4 last
}

test "executor - simple shell step execution" {
    const allocator = std.testing.allocator;

    var executor = Executor.init(allocator, null, 1);

    // Create simple workflow with one shell step
    // Note: Using /bin/echo instead of shell builtin since we no longer use sh -c
    var config_obj = std.json.ObjectMap.init(allocator);
    // Allocate both key and value so they can be properly freed
    const key1 = try allocator.dupe(u8, "cmd");
    try config_obj.put(key1, .{ .string = try allocator.dupe(u8, "/bin/echo hello") });

    var step1 = plan.Step{
        .id = try allocator.dupe(u8, "step1"),
        .name = try allocator.dupe(u8, "Echo test"),
        .type = .shell,
        .config = .{ .data = .{ .object = config_obj } },
        .depends_on = &[_][]const u8{},
    };
    defer step1.deinit(allocator);

    var steps = [_]plan.Step{step1};
    const workflow = plan.WorkflowDefinition{
        .name = "test",
        .triggers = @constCast(&[_]plan.Trigger{}),
        .image = null,
        .dockerfile = null,
        .steps = &steps,
    };

    const results = try executor.execute(&workflow, 1);
    defer {
        for (results) |*result| {
            result.deinit(allocator);
        }
        allocator.free(results);
    }

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(StepStatus.succeeded, results[0].status);
    try std.testing.expectEqual(@as(i32, 0), results[0].exit_code.?);
}

test "executor - shell step with actual output" {
    const allocator = std.testing.allocator;

    var executor = Executor.init(allocator, null, 1);

    // Create workflow that produces output
    // Note: No quotes needed since we're not using shell parsing
    var config_obj = std.json.ObjectMap.init(allocator);
    // Allocate both key and value so they can be properly freed
    const key1 = try allocator.dupe(u8, "cmd");
    try config_obj.put(key1, .{ .string = try allocator.dupe(u8, "/bin/echo test output") });

    var step1 = plan.Step{
        .id = try allocator.dupe(u8, "step1"),
        .name = try allocator.dupe(u8, "Output test"),
        .type = .shell,
        .config = .{ .data = .{ .object = config_obj } },
        .depends_on = &[_][]const u8{},
    };
    defer step1.deinit(allocator);

    var steps = [_]plan.Step{step1};
    const workflow = plan.WorkflowDefinition{
        .name = "test",
        .triggers = @constCast(&[_]plan.Trigger{}),
        .image = null,
        .dockerfile = null,
        .steps = &steps,
    };

    const results = try executor.execute(&workflow, 1);
    defer {
        for (results) |*result| {
            result.deinit(allocator);
        }
        allocator.free(results);
    }

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(StepStatus.succeeded, results[0].status);

    // Check output exists
    try std.testing.expect(results[0].output != null);
    if (results[0].output) |output| {
        try std.testing.expect(output == .object);
        const stdout = output.object.get("stdout");
        try std.testing.expect(stdout != null);
    }
}

test "executor - shell step failure" {
    const allocator = std.testing.allocator;

    var executor = Executor.init(allocator, null, 1);

    // Create workflow with failing command
    // Note: Using /usr/bin/false instead of shell builtin exit
    var config_obj = std.json.ObjectMap.init(allocator);
    // Allocate both key and value so they can be properly freed
    const key1 = try allocator.dupe(u8, "cmd");
    try config_obj.put(key1, .{ .string = try allocator.dupe(u8, "/usr/bin/false") });

    var step1 = plan.Step{
        .id = try allocator.dupe(u8, "step1"),
        .name = try allocator.dupe(u8, "Failing step"),
        .type = .shell,
        .config = .{ .data = .{ .object = config_obj } },
        .depends_on = &[_][]const u8{},
    };
    defer step1.deinit(allocator);

    var steps = [_]plan.Step{step1};
    const workflow = plan.WorkflowDefinition{
        .name = "test",
        .triggers = @constCast(&[_]plan.Trigger{}),
        .image = null,
        .dockerfile = null,
        .steps = &steps,
    };

    const results = try executor.execute(&workflow, 1);
    defer {
        for (results) |*result| {
            result.deinit(allocator);
        }
        allocator.free(results);
    }

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(StepStatus.failed, results[0].status);
    try std.testing.expectEqual(@as(i32, 1), results[0].exit_code.?);
}

test "executor - dependency skipping" {
    const allocator = std.testing.allocator;

    var executor = Executor.init(allocator, null, 1);

    // Create workflow: step1 (fails) -> step2 (should be skipped)
    var config1_obj = std.json.ObjectMap.init(allocator);
    // Allocate both key and value so they can be properly freed by step.deinit()
    const key1 = try allocator.dupe(u8, "cmd");
    try config1_obj.put(key1, .{ .string = try allocator.dupe(u8, "/usr/bin/false") });

    const step1_deps = try allocator.alloc([]const u8, 0);
    var step1 = plan.Step{
        .id = try allocator.dupe(u8, "step1"),
        .name = try allocator.dupe(u8, "Failing step"),
        .type = .shell,
        .config = .{ .data = .{ .object = config1_obj } },
        .depends_on = step1_deps,
    };
    defer step1.deinit(allocator);

    var config2_obj = std.json.ObjectMap.init(allocator);
    // Allocate both key and value so they can be properly freed by step.deinit()
    const key2 = try allocator.dupe(u8, "cmd");
    try config2_obj.put(key2, .{ .string = try allocator.dupe(u8, "/bin/echo should not run") });

    const step2_deps = try allocator.alloc([]const u8, 1);
    step2_deps[0] = try allocator.dupe(u8, "step1");
    var step2 = plan.Step{
        .id = try allocator.dupe(u8, "step2"),
        .name = try allocator.dupe(u8, "Dependent step"),
        .type = .shell,
        .config = .{ .data = .{ .object = config2_obj } },
        .depends_on = step2_deps,
    };
    defer {
        step2.deinit(allocator);
    }

    var steps = [_]plan.Step{ step1, step2 };
    const workflow = plan.WorkflowDefinition{
        .name = "test",
        .triggers = @constCast(&[_]plan.Trigger{}),
        .image = null,
        .dockerfile = null,
        .steps = &steps,
    };

    const results = try executor.execute(&workflow, 1);
    defer {
        for (results) |*result| {
            result.deinit(allocator);
        }
        allocator.free(results);
    }

    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqual(StepStatus.failed, results[0].status);
    try std.testing.expectEqual(StepStatus.skipped, results[1].status);
}

test "executor - environment variables" {
    const allocator = std.testing.allocator;

    var executor = Executor.init(allocator, null, 1);

    // Create workflow with environment variables
    // Note: Direct argv execution doesn't expand env vars like shell does
    // Using /usr/bin/env to print environment variable
    var config_obj = std.json.ObjectMap.init(allocator);
    // Allocate both keys and values so they can be properly freed by step.deinit()
    const key_cmd = try allocator.dupe(u8, "cmd");
    try config_obj.put(key_cmd, .{ .string = try allocator.dupe(u8, "/usr/bin/printenv TEST_VAR") });

    var env_obj = std.json.ObjectMap.init(allocator);
    const key_test_var = try allocator.dupe(u8, "TEST_VAR");
    try env_obj.put(key_test_var, .{ .string = try allocator.dupe(u8, "test_value") });
    const key_env = try allocator.dupe(u8, "env");
    try config_obj.put(key_env, .{ .object = env_obj });

    const step1_deps = try allocator.alloc([]const u8, 0);
    var step1 = plan.Step{
        .id = try allocator.dupe(u8, "step1"),
        .name = try allocator.dupe(u8, "Env test"),
        .type = .shell,
        .config = .{ .data = .{ .object = config_obj } },
        .depends_on = step1_deps,
    };
    defer step1.deinit(allocator);

    var steps = [_]plan.Step{step1};
    const workflow = plan.WorkflowDefinition{
        .name = "test",
        .triggers = @constCast(&[_]plan.Trigger{}),
        .image = null,
        .dockerfile = null,
        .steps = &steps,
    };

    const results = try executor.execute(&workflow, 1);
    defer {
        for (results) |*result| {
            result.deinit(allocator);
        }
        allocator.free(results);
    }

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(StepStatus.succeeded, results[0].status);

    // Check that environment variable was used
    if (results[0].output) |output| {
        if (output == .object) {
            if (output.object.get("stdout")) |stdout_value| {
                if (stdout_value == .string) {
                    try std.testing.expect(std.mem.indexOf(u8, stdout_value.string, "test_value") != null);
                }
            }
        }
    }
}
// Global event mutex to serialize callbacks coming from parallel workers.
var g_event_mutex: std.Thread.Mutex = .{};

test "executor - parallel group independent branches succeed and preserve outputs" {
    const allocator = std.testing.allocator;

    var executor = Executor.init(allocator, null, 1);

    // Two echo steps to run in parallel
    var cfg1 = std.json.ObjectMap.init(allocator);
    const k_cmd1 = try allocator.dupe(u8, "cmd");
    try cfg1.put(k_cmd1, .{ .string = try allocator.dupe(u8, "/bin/echo one") });

    var s1 = plan.Step{
        .id = try allocator.dupe(u8, "s1"),
        .name = try allocator.dupe(u8, "one"),
        .type = .shell,
        .config = .{ .data = .{ .object = cfg1 } },
        .depends_on = &.{},
    };
    defer s1.deinit(allocator);

    var cfg2 = std.json.ObjectMap.init(allocator);
    const k_cmd2 = try allocator.dupe(u8, "cmd");
    try cfg2.put(k_cmd2, .{ .string = try allocator.dupe(u8, "/bin/echo two") });

    var s2 = plan.Step{
        .id = try allocator.dupe(u8, "s2"),
        .name = try allocator.dupe(u8, "two"),
        .type = .shell,
        .config = .{ .data = .{ .object = cfg2 } },
        .depends_on = &.{},
    };
    defer s2.deinit(allocator);

    // Parallel group referencing s1 and s2
    var step_ids = std.json.Array.init(allocator);
    try step_ids.append(.{ .string = try allocator.dupe(u8, "s1") });
    try step_ids.append(.{ .string = try allocator.dupe(u8, "s2") });
    var p_cfg = std.json.ObjectMap.init(allocator);
    const k_ids = try allocator.dupe(u8, "step_ids");
    try p_cfg.put(k_ids, .{ .array = step_ids });

    var p = plan.Step{
        .id = try allocator.dupe(u8, "p"),
        .name = try allocator.dupe(u8, "parallel"),
        .type = .parallel,
        .config = .{ .data = .{ .object = p_cfg } },
        .depends_on = &.{},
    };
    defer p.deinit(allocator);

    var steps = [_]plan.Step{ s1, s2, p };
    const workflow = plan.WorkflowDefinition{
        .name = "test",
        .triggers = @constCast(&[_]plan.Trigger{}),
        .image = null,
        .dockerfile = null,
        .steps = &steps,
    };

    const results = try executor.execute(&workflow, 1);
    defer {
        for (results) |*r| r.deinit(allocator);
        allocator.free(results);
    }

    // Map results by id
    var got_s1 = false;
    var got_s2 = false;
    var group_ok = false;
    for (results) |r| {
        if (std.mem.eql(u8, r.step_id, "s1")) {
            try std.testing.expectEqual(StepStatus.succeeded, r.status);
            try std.testing.expect(r.output != null);
            got_s1 = true;
        } else if (std.mem.eql(u8, r.step_id, "s2")) {
            try std.testing.expectEqual(StepStatus.succeeded, r.status);
            try std.testing.expect(r.output != null);
            got_s2 = true;
        } else if (std.mem.eql(u8, r.step_id, "p")) {
            group_ok = (r.status == .succeeded);
        }
    }
    try std.testing.expect(got_s1 and got_s2 and group_ok);
}

test "executor - parallel intra-group dependency runs in later layer" {
    const allocator = std.testing.allocator;
    var executor = Executor.init(allocator, null, 1);

    // a -> b, both inside the same parallel group
    var cfg_a = std.json.ObjectMap.init(allocator);
    const k_cmd_a = try allocator.dupe(u8, "cmd");
    try cfg_a.put(k_cmd_a, .{ .string = try allocator.dupe(u8, "/bin/echo a") });
    var a = plan.Step{
        .id = try allocator.dupe(u8, "a"),
        .name = try allocator.dupe(u8, "a"),
        .type = .shell,
        .config = .{ .data = .{ .object = cfg_a } },
        .depends_on = &.{},
    };
    defer a.deinit(allocator);

    var cfg_b = std.json.ObjectMap.init(allocator);
    const k_cmd_b = try allocator.dupe(u8, "cmd");
    try cfg_b.put(k_cmd_b, .{ .string = try allocator.dupe(u8, "/bin/echo b") });
    const b_deps = try allocator.alloc([]const u8, 1);
    b_deps[0] = try allocator.dupe(u8, "a");
    var b = plan.Step{
        .id = try allocator.dupe(u8, "b"),
        .name = try allocator.dupe(u8, "b"),
        .type = .shell,
        .config = .{ .data = .{ .object = cfg_b } },
        .depends_on = b_deps,
    };
    defer b.deinit(allocator);

    var ids = std.json.Array.init(allocator);
    try ids.append(.{ .string = try allocator.dupe(u8, "a") });
    try ids.append(.{ .string = try allocator.dupe(u8, "b") });
    var cfg_p = std.json.ObjectMap.init(allocator);
    try cfg_p.put(try allocator.dupe(u8, "step_ids"), .{ .array = ids });
    var p = plan.Step{
        .id = try allocator.dupe(u8, "pg"),
        .name = try allocator.dupe(u8, "pg"),
        .type = .parallel,
        .config = .{ .data = .{ .object = cfg_p } },
        .depends_on = &.{},
    };
    defer p.deinit(allocator);

    var steps = [_]plan.Step{ a, b, p };
    const wf = plan.WorkflowDefinition{
        .name = "test",
        .triggers = @constCast(&[_]plan.Trigger{}),
        .image = null,
        .dockerfile = null,
        .steps = &steps,
    };

    const results = try executor.execute(&wf, 1);
    defer { for (results) |*r| r.deinit(allocator); allocator.free(results); }

    var a_ok = false;
    var b_ok = false;
    for (results) |r| {
        if (std.mem.eql(u8, r.step_id, "a")) a_ok = (r.status == .succeeded);
        if (std.mem.eql(u8, r.step_id, "b")) b_ok = (r.status == .succeeded);
    }
    try std.testing.expect(a_ok and b_ok);
}

test "executor - parallel branch failure marks group failed (default policy)" {
    const allocator = std.testing.allocator;
    var executor = Executor.init(allocator, null, 1);

    // f fails, g succeeds
    var cfg_f = std.json.ObjectMap.init(allocator);
    try cfg_f.put(try allocator.dupe(u8, "cmd"), .{ .string = try allocator.dupe(u8, "/usr/bin/false") });
    var f = plan.Step{ .id = try allocator.dupe(u8, "f"), .name = try allocator.dupe(u8, "f"), .type = .shell, .config = .{ .data = .{ .object = cfg_f } }, .depends_on = &.{} };
    defer f.deinit(allocator);

    var cfg_g = std.json.ObjectMap.init(allocator);
    try cfg_g.put(try allocator.dupe(u8, "cmd"), .{ .string = try allocator.dupe(u8, "/bin/echo ok") });
    var g = plan.Step{ .id = try allocator.dupe(u8, "g"), .name = try allocator.dupe(u8, "g"), .type = .shell, .config = .{ .data = .{ .object = cfg_g } }, .depends_on = &.{} };
    defer g.deinit(allocator);

    var ids = std.json.Array.init(allocator);
    try ids.append(.{ .string = try allocator.dupe(u8, "f") });
    try ids.append(.{ .string = try allocator.dupe(u8, "g") });
    var cfg_p = std.json.ObjectMap.init(allocator);
    try cfg_p.put(try allocator.dupe(u8, "step_ids"), .{ .array = ids });
    var p = plan.Step{ .id = try allocator.dupe(u8, "P"), .name = try allocator.dupe(u8, "P"), .type = .parallel, .config = .{ .data = .{ .object = cfg_p } }, .depends_on = &.{} };
    defer p.deinit(allocator);

    var steps = [_]plan.Step{ f, g, p };
    const wf = plan.WorkflowDefinition{ .name = "t", .triggers = @constCast(&[_]plan.Trigger{}), .image = null, .dockerfile = null, .steps = &steps };
    const results = try executor.execute(&wf, 1);
    defer { for (results) |*r| r.deinit(allocator); allocator.free(results); }

    var group_failed = false;
    var g_ok = false;
    for (results) |r| {
        if (std.mem.eql(u8, r.step_id, "P")) group_failed = (r.status == .failed);
        if (std.mem.eql(u8, r.step_id, "g")) g_ok = (r.status == .succeeded);
    }
    try std.testing.expect(group_failed and g_ok);
}

test "executor - parallel fail_fast cancels remaining when max_concurrency=1" {
    const allocator = std.testing.allocator;
    var executor = Executor.init(allocator, null, 1);

    // First fails, second would be cancelled under fail_fast with single concurrency
    var cfg_a = std.json.ObjectMap.init(allocator);
    try cfg_a.put(try allocator.dupe(u8, "cmd"), .{ .string = try allocator.dupe(u8, "/usr/bin/false") });
    var a = plan.Step{ .id = try allocator.dupe(u8, "aa"), .name = try allocator.dupe(u8, "aa"), .type = .shell, .config = .{ .data = .{ .object = cfg_a } }, .depends_on = &.{} };
    defer a.deinit(allocator);

    var cfg_b = std.json.ObjectMap.init(allocator);
    try cfg_b.put(try allocator.dupe(u8, "cmd"), .{ .string = try allocator.dupe(u8, "/bin/echo ok") });
    var b = plan.Step{ .id = try allocator.dupe(u8, "bb"), .name = try allocator.dupe(u8, "bb"), .type = .shell, .config = .{ .data = .{ .object = cfg_b } }, .depends_on = &.{} };
    defer b.deinit(allocator);

    var ids = std.json.Array.init(allocator);
    try ids.append(.{ .string = try allocator.dupe(u8, "aa") });
    try ids.append(.{ .string = try allocator.dupe(u8, "bb") });
    var cfg_p = std.json.ObjectMap.init(allocator);
    try cfg_p.put(try allocator.dupe(u8, "step_ids"), .{ .array = ids });
    try cfg_p.put(try allocator.dupe(u8, "failure_mode"), .{ .string = try allocator.dupe(u8, "fail_fast") });
    try cfg_p.put(try allocator.dupe(u8, "max_concurrency"), .{ .integer = 1 });
    var p = plan.Step{ .id = try allocator.dupe(u8, "PF"), .name = try allocator.dupe(u8, "PF"), .type = .parallel, .config = .{ .data = .{ .object = cfg_p } }, .depends_on = &.{} };
    defer p.deinit(allocator);

    var steps = [_]plan.Step{ a, b, p };
    const wf = plan.WorkflowDefinition{ .name = "t", .triggers = @constCast(&[_]plan.Trigger{}), .image = null, .dockerfile = null, .steps = &steps };
    const results = try executor.execute(&wf, 1);
    defer { for (results) |*r| r.deinit(allocator); allocator.free(results); }

    var saw_cancelled = false;
    var group_failed = false;
    for (results) |r| {
        if (std.mem.eql(u8, r.step_id, "bb")) saw_cancelled = (r.status == .cancelled or r.status == .skipped);
        if (std.mem.eql(u8, r.step_id, "PF")) group_failed = (r.status == .failed);
    }
    try std.testing.expect(saw_cancelled and group_failed);
}

test "executor - parallel emits step events for branches and group" {
    const allocator = std.testing.allocator;
    var executor = Executor.init(allocator, null, 1);

    const Ctx = struct { var started: usize = 0; var completed: usize = 0; };
    const cb = struct {
        fn handler(ev: ExecutionEvent, ctx: ?*anyopaque) void {
            _ = ctx; // not used
            switch (ev) {
                .step_started => Ctx.started += 1,
                .step_completed => Ctx.completed += 1,
                else => {},
            }
        }
    }.handler;
    executor.setEventCallback(cb, null);

    // trivial parallel
    var c1 = std.json.ObjectMap.init(allocator);
    try c1.put(try allocator.dupe(u8, "cmd"), .{ .string = try allocator.dupe(u8, "/bin/echo x") });
    var s1 = plan.Step{ .id = try allocator.dupe(u8, "e1"), .name = try allocator.dupe(u8, "e1"), .type = .shell, .config = .{ .data = .{ .object = c1 } }, .depends_on = &.{} };
    defer s1.deinit(allocator);
    var c2 = std.json.ObjectMap.init(allocator);
    try c2.put(try allocator.dupe(u8, "cmd"), .{ .string = try allocator.dupe(u8, "/bin/echo y") });
    var s2 = plan.Step{ .id = try allocator.dupe(u8, "e2"), .name = try allocator.dupe(u8, "e2"), .type = .shell, .config = .{ .data = .{ .object = c2 } }, .depends_on = &.{} };
    defer s2.deinit(allocator);

    var ids = std.json.Array.init(allocator);
    try ids.append(.{ .string = try allocator.dupe(u8, "e1") });
    try ids.append(.{ .string = try allocator.dupe(u8, "e2") });
    var pc = std.json.ObjectMap.init(allocator);
    try pc.put(try allocator.dupe(u8, "step_ids"), .{ .array = ids });
    var p = plan.Step{ .id = try allocator.dupe(u8, "EG"), .name = try allocator.dupe(u8, "EG"), .type = .parallel, .config = .{ .data = .{ .object = pc } }, .depends_on = &.{} };
    defer p.deinit(allocator);

    var steps = [_]plan.Step{ s1, s2, p };
    const wf = plan.WorkflowDefinition{ .name = "t", .triggers = @constCast(&[_]plan.Trigger{}), .image = null, .dockerfile = null, .steps = &steps };
    const results = try executor.execute(&wf, 1);
    defer { for (results) |*r| r.deinit(allocator); allocator.free(results); }

    // Expect at least 3 started/completed (2 branches + group)
    try std.testing.expect(Ctx.started >= 3 and Ctx.completed >= 3);
}
