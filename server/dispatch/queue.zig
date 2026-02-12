//! Task Queue Management
//!
//! Manages workload queue with warm pool runner assignment.
//! Provides <500ms assignment for interactive agents when runners are available.

const std = @import("std");
const db = @import("db");
const workflows = @import("../workflows/mod.zig");

const log = std.log.scoped(.queue);

/// Workload type
pub const WorkloadType = enum {
    agent, // AI agent execution
    workflow, // Traditional CI workflow
};

/// Workload status
pub const WorkloadStatus = enum {
    pending, // Waiting for runner
    assigned, // Runner assigned, waiting to start
    running, // Executing
    completed, // Finished successfully
    failed, // Execution failed
    cancelled, // Cancelled by user
};

/// Priority levels
pub const Priority = enum(u8) {
    low = 0,
    normal = 1,
    high = 2,
    critical = 3,
};

/// Workload submission request
pub const WorkloadRequest = struct {
    type: WorkloadType,
    workflow_run_id: ?i32,
    session_id: ?[]const u8,
    priority: Priority,
    // Optional JSON config to pass to the runner. For workflow tasks
    // we will populate per-step configs automatically.
    config_json: ?[]const u8,
    // Optional label requirements for runner selection. If null, defaults
    // to empty array []. Labels are enforced both in push- and pull-paths.
    required_labels: ?[]const []const u8 = null,
};

/// Runner information
pub const Runner = struct {
    id: i32,
    pod_name: []const u8,
    pod_ip: []const u8,
    status: RunnerStatus,
    registered_at: i64,
    last_heartbeat: i64,
};

pub const RunnerStatus = enum {
    available,
    claimed,
    terminated,
};

/// Submit a workload to the queue
pub fn submitWorkload(
    allocator: std.mem.Allocator,
    pool: *db.Pool,
    request: WorkloadRequest,
) !i32 {
    log.info("Submitting workload: type={s}, priority={d}", .{
        @tagName(request.type),
        @intFromEnum(request.priority),
    });

    const workload_type_txt = switch (request.type) {
        .agent => "agent",
        .workflow => "workflow",
    };

    // Encode labels to JSON once for reuse (dynamic, no fixed buffer limits)
    const labels_json: ?[]const u8 = blk: {
        if (request.required_labels) |labels| {
            var list = std.ArrayList(u8){};
            defer list.deinit(allocator);
            const w = list.writer(allocator);
            try w.writeByte('[');
            var count: usize = 0;
            for (labels) |lab| {
                if (lab.len == 0) continue;
                if (count > 0) try w.writeByte(',');
                try std.json.stringify(lab, .{}, w);
                count += 1;
            }
            try w.writeByte(']');
            break :blk try list.toOwnedSlice(allocator);
        }
        break :blk null;
    };
    defer if (labels_json) |lj| allocator.free(lj);

    if (request.type == .workflow and request.workflow_run_id) |run_id| {
        // Single-job approach: create ONE task with full workflow payload
        const cfg_json = try buildWorkflowConfigJson(allocator, pool, run_id);
        defer allocator.free(cfg_json);

        const tid = try db.workflows.createWorkflowTask(
            pool,
            workload_type_txt,
            request.workflow_run_id,
            request.session_id,
            @intFromEnum(request.priority),
            labels_json,
            cfg_json,
        );

        const cfg = @import("../config.zig").load();
        if (cfg.local_dev_sync) executeWorkflowAsync(allocator, pool, run_id);
        return tid;
    } else {
        // Agent or non-workflow task
        // Ensure config includes explicit type for the Python runner
        const agent_cfg = blk: {
            if (request.config_json) |cj| {
                // If caller already provided, ensure it contains a type; if not, wrap it
                if (std.mem.indexOf(u8, cj, "\"type\"")) |_| {
                    break :blk cj;
                }
                var list = std.ArrayList(u8){};
                defer list.deinit(allocator);
                const w = list.writer(allocator);
                try w.writeAll("{\"type\":\"agent\",\"config\":");
                try w.writeAll(cj);
                try w.writeByte('}');
                break :blk try list.toOwnedSlice(allocator);
            }
            break :blk "{\"type\":\"agent\"}";
        };

        const task_id = try db.workflows.createWorkflowTask(
            pool,
            workload_type_txt,
            request.workflow_run_id,
            request.session_id,
            @intFromEnum(request.priority),
            labels_json,
            agent_cfg,
        );
        return task_id;
    }
}

/// Insert workflow_tasks for each step in the workflow run's plan.
/// Build the Python-runner workflow config JSON for a given run_id.
/// Shape: {"type":"workflow", "steps":[ ... ]}
fn buildWorkflowConfigJson(
    allocator: std.mem.Allocator,
    pool: *db.Pool,
    run_id: i32,
) ![]const u8 {
    // Resolve workflow definition for the run
    const row = try pool.row(
        \\SELECT workflow_definition_id FROM workflow_runs WHERE id = $1
    , .{run_id});
    if (row == null) return error.WorkflowRunNotFound;
    const def_id = row.?.get(?i32, 0) orelse return error.WorkflowDefinitionNotFound;

    const def = try db.workflows.getWorkflowDefinition(pool, def_id) orelse return error.WorkflowDefinitionNotFound;

    // Parse plan JSON
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parsed = try std.json.parseFromSlice(
        workflows.plan.WorkflowDefinition,
        a,
        def.plan,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var out = std.ArrayList(u8){};
    errdefer out.deinit(allocator);
    const w = out.writer(allocator);

    try w.writeAll("{\"type\":\"workflow\",\"steps\":[");

    var first: bool = true;
    for (parsed.value.steps) |step| {
        if (!first) try w.writeByte(',');
        first = false;

        switch (step.\@"type") {
            .shell => {
                // Map shell step to runner's {type:"run", run:"<cmd>", env:{...}}
                const cfg = step.config.data;
                var cmd: ?[]const u8 = null;
                var env_json: ?[]const u8 = null;
                if (cfg == .object) {
                    if (cfg.object.get("cmd")) |v| if (v == .string) cmd = v.string;
                    if (cfg.object.get("env")) |v| {
                        // Serialize env object directly as JSON
                        const json_util = @import("../lib/json.zig");
                        env_json = json_util.valueToString(allocator, v) catch null;
                    }
                }
                try w.writeByte('{');
                // name
                try w.writeAll("\"name\":");
                try std.json.stringify(step.name, .{}, w);
                // type
                try w.writeAll(",\"type\":\"run\"");
                // run command
                if (cmd) |c| {
                    try w.writeAll(",\"run\":");
                    try std.json.stringify(c, .{}, w);
                } else {
                    // Fallback: no cmd provided, emit a harmless echo
                    try w.writeAll(",\"run\":\"/bin/echo Missing cmd in shell step\"");
                }
                // env if present
                if (env_json) |ej| {
                    try w.writeAll(",\"env\":");
                    try w.writeAll(ej);
                    allocator.free(ej);
                }
                try w.writeByte('}');
            },
            else => {
                // Unsupported step types: emit a no-op log via echo
                try w.writeAll("{\"name\":");
                try std.json.stringify(step.name, .{}, w);
                try w.writeAll(",\"type\":\"run\",\"run\":\"/bin/echo Skipping unsupported step type\"}");
            },
        }
    }

    try w.writeAll("]}");
    return try out.toOwnedSlice(allocator);
}

/// Execute a workflow asynchronously (for local development)
fn executeWorkflowAsync(parent_allocator: std.mem.Allocator, pool: *db.Pool, run_id: i32) void {
    // Create a thread-local arena allocator for this execution
    // This ensures thread safety and makes cleanup easier
    var arena = std.heap.ArenaAllocator.init(parent_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    executeWorkflow(allocator, pool, run_id) catch |err| {
        log.err("Workflow execution failed for run_id={d}: {}", .{ run_id, err });

        // Mark workflow as failed
        const fail_query =
            \\UPDATE workflow_runs
            \\SET status = 'failed', completed_at = NOW(), error_message = $1
            \\WHERE id = $2
        ;
        const err_msg = @errorName(err);
        _ = pool.query(fail_query, .{ err_msg, run_id }) catch |query_err| {
            log.err("Failed to update workflow status: {}", .{query_err});
        };
    };
    // Arena allocator automatically frees all memory when this function returns
}

/// Execute a workflow (synchronous)
fn executeWorkflow(allocator: std.mem.Allocator, pool: *db.Pool, run_id: i32) !void {
    log.info("Starting workflow execution for run_id={d}", .{run_id});

    // 1. Get the workflow run to find the workflow_definition_id
    const run_query =
        \\SELECT workflow_definition_id
        \\FROM workflow_runs
        \\WHERE id = $1
    ;

    const run_result = try pool.query(run_query, .{run_id});
    defer run_result.deinit();

    const workflow_def_id = if (try run_result.next()) |row|
        row.get(i32, 0)
    else
        return error.WorkflowRunNotFound;

    log.info("Found workflow_definition_id={d}", .{workflow_def_id});

    // 2. Get the workflow definition (includes the plan JSON)
    const workflow_def_opt = try db.workflows.getWorkflowDefinition(pool, workflow_def_id);
    const workflow_def = workflow_def_opt orelse return error.WorkflowDefinitionNotFound;

    log.info("Loaded workflow definition: {s}", .{workflow_def.name});
    log.info("Plan JSON length: {d} bytes", .{workflow_def.plan.len});
    log.info("Plan JSON: {s}", .{workflow_def.plan});

    // 3. Parse the plan JSON
    const parsed = std.json.parseFromSlice(
        workflows.plan.WorkflowDefinition,
        allocator,
        workflow_def.plan,
        .{ .ignore_unknown_fields = true }, // Ignore unknown fields for now
    ) catch |err| {
        log.err("Failed to parse plan JSON: {}", .{err});
        log.err("Plan JSON was: {s}", .{workflow_def.plan});
        return err;
    };
    defer parsed.deinit();

    const workflow_plan = parsed.value;

    log.info("Parsed workflow plan: {s}, steps={d}", .{ workflow_plan.name, workflow_plan.steps.len });

    // 4. Initialize executor
    var exec = workflows.Executor.init(allocator, pool, run_id);

    // 5. Execute workflow
    const results = try exec.execute(&workflow_plan, run_id);
    defer {
        for (results) |*result| {
            result.deinit(allocator);
        }
        allocator.free(results);
    }

    // 6. Determine overall success
    var all_succeeded = true;
    for (results) |result| {
        if (result.status != .succeeded and result.status != .skipped) {
            all_succeeded = false;
            break;
        }
    }

    // 7. Update workflow_run status
    const status = if (all_succeeded) "completed" else "failed";
    const complete_query =
        \\UPDATE workflow_runs
        \\SET status = $1, completed_at = NOW()
        \\WHERE id = $2
    ;
    _ = try pool.query(complete_query, .{ status, run_id });

    log.info("Workflow execution completed: run_id={d}, status={s}", .{ run_id, status });
}

/// Try to assign a warm runner to a task
/// Try to assign a warm runner to a task (push path)
/// Push-path assignment is disabled. Runners pull tasks via /internal/runners/register.
pub fn tryAssignRunner(pool: *db.Pool, task_id: i32) !void {
    _ = pool;
    _ = task_id;
    return error.NoAvailableRunner;
}

/// Register a runner in the warm pool
// Deprecated register/updateHeartbeat helpers kept temporarily for compatibility with old callers
pub fn registerRunner(pool: *db.Pool, pod_name: []const u8, pod_ip: []const u8) !i32 {
    log.warn("queue.registerRunner is deprecated; use RunnerPool DAO via internal routes", .{});
    const row = try pool.row(
        \\INSERT INTO runner_pool (pod_name, pod_ip, status, registered_at, last_heartbeat)
        \\VALUES ($1, $2, 'available', NOW(), NOW())
        \\ON CONFLICT (pod_name) DO UPDATE SET pod_ip=$2, status='available', last_heartbeat=NOW()
        \\RETURNING id
    , .{ pod_name, pod_ip });
    if (row) |r| return r.get(i32, 0);
    return error.FailedToRegisterRunner;
}

pub fn updateHeartbeat(pool: *db.Pool, pod_name: []const u8) !void {
    log.warn("queue.updateHeartbeat is deprecated; prefer /internal/runners/:runner_id/heartbeat", .{});
    _ = try pool.exec(
        \\UPDATE runner_pool SET last_heartbeat = NOW() WHERE pod_name = $1 AND status != 'terminated'
    , .{pod_name});
}

/// Mark task as completed
pub fn completeTask(pool: *db.Pool, task_id: i32, success: bool) !void {
    try db.workflows.completeWorkflowTask(pool, task_id, success, null);
    try db.workflows.releaseRunnerByTask(pool, task_id);

    const row = try pool.row(
        \SELECT workflow_run_id FROM workflow_tasks WHERE id = $1
    , .{task_id});
    if (row) |r| {
        if (r.get(?i32, 0)) |run_id| {
            // Aggregate all tasks for the run
            const agg = try pool.row(
                \\SELECT
                \\  COUNT(*)::int AS total,
                \\  SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END)::int AS completed,
                \\  SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)::int AS failed
                \\FROM workflow_tasks WHERE workflow_run_id = $1
            , .{run_id});
            if (agg) |a| {
                const total = a.get(i32, 0);
                const completed = a.get(i32, 1);
                const failed = a.get(i32, 2);
                if (failed > 0) {
                    _ = try pool.exec(
                        \\UPDATE workflow_runs SET status = 'failed', completed_at = NOW() WHERE id = $1
                    , .{ run_id });
                } else if (total > 0 and completed == total) {
                    _ = try pool.exec(
                        \\UPDATE workflow_runs SET status = 'completed', completed_at = NOW() WHERE id = $1
                    , .{ run_id });
                } else {
                    // Ensure run is at least marked running once tasks start/finish
                    _ = try pool.exec(
                        \\UPDATE workflow_runs SET status = 'running' WHERE id = $1 AND status = 'pending'
                    , .{ run_id });
                }
            }
        }
    }
    log.info("Task {d} completed (success={})", .{ task_id, success });
}

/// Mark task failed with error message
pub fn completeTaskWithError(pool: *db.Pool, task_id: i32, message: []const u8) !void {
    try db.workflows.completeWorkflowTask(pool, task_id, false, message);
    try db.workflows.releaseRunnerByTask(pool, task_id);

    const row = try pool.row(
        \SELECT workflow_run_id FROM workflow_tasks WHERE id = $1
    , .{task_id});
    if (row) |r| {
        if (r.get(?i32, 0)) |run_id| {
            _ = try pool.exec(
                \UPDATE workflow_runs SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1
            , .{ run_id, message });
        }
    }
}


/// Get pending task for runner (used in standby mode)
pub fn getPendingTaskForRunner(
    allocator: std.mem.Allocator,
    pool: *db.Pool,
    runner_id: i32,
) !?TaskAssignment {
    _ = allocator;
    const claim = try db.workflows.claimPendingTaskForRunner(pool, runner_id) orelse return null;
    return TaskAssignment{
        .task_id = claim.task_id,
        .config_json = claim.config_json,
        .workload_type = claim.workload_type,
        .session_id = claim.session_id,
        .workflow_name = null,
    };
}

pub const TaskAssignment = struct {
    task_id: i32,
    config_json: ?[]const u8,
    workload_type: []const u8,
    session_id: ?[]const u8,
    workflow_name: ?[]const u8,
};

// =============================================================================
// Tests
// =============================================================================

test "Priority ordering" {
    try std.testing.expect(@intFromEnum(Priority.high) > @intFromEnum(Priority.normal));
    try std.testing.expect(@intFromEnum(Priority.critical) > @intFromEnum(Priority.high));
}

test "WorkloadStatus enum" {
    const status: WorkloadStatus = .pending;
    try std.testing.expectEqual(WorkloadStatus.pending, status);
}

/// Transition a task to running when runner starts sending events
pub fn markTaskRunning(pool: *db.Pool, task_id: i32) !void {
    try db.workflows.markTaskRunning(pool, task_id);
    // If this task is associated with a run, mark the run as running
    const row = try pool.row(
        \SELECT workflow_run_id FROM workflow_tasks WHERE id = $1
    , .{task_id});
    if (row) |r| {
        if (r.get(?i32, 0)) |run_id| {
            _ = try pool.exec(
                \UPDATE workflow_runs SET status = 'running', started_at = COALESCE(started_at, NOW()) WHERE id = $1 AND status = 'pending'
            , .{ run_id });
        }
    }
}

/// Requeue tasks with stale/terminated runners and release orphaned claims
pub fn recoverStuckTasks(pool: *db.Pool) !void {
    const requeued = try db.workflows.requeueStuckTasks(pool);
    const released = try db.workflows.releaseOrphanedRunners(pool);
    log.info("Queue recovery: requeued={d}, released_runners={d}", .{ requeued, released });
}
