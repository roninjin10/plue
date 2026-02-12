//! Plue CLI - Workflow and Prompt Management
//!
//! Commands:
//!   plue workflow list                     - List all workflows
//!   plue workflow run <name>               - Run workflow manually
//!   plue workflow run <name> --input k=v   - Run with inputs
//!   plue workflow lint                     - Lint .py and .prompt.md files
//!   plue run list                          - List recent runs
//!   plue run view <run-id>                 - View run details
//!   plue run watch <run-id>                - Watch live run (SSE stream)
//!   plue run cancel <run-id>               - Cancel running workflow
//!   plue prompt preview <file>             - Render prompt with sample inputs
//!   plue prompt test <file>                - Test prompt execution

const std = @import("std");
const workflows = @import("workflows/mod.zig");
const ssh_security = @import("ssh/security_log.zig");

const db = @import("db");
const log = std.log.scoped(.cli);

// Simple writer wrappers for stdout/stderr using std.debug.print
const StdoutWriter = struct {
    pub const Error = error{};
    pub const Writer = std.io.Writer(StdoutWriter, Error, write);

    pub fn write(self: StdoutWriter, bytes: []const u8) Error!usize {
        _ = self;
        std.debug.print("{s}", .{bytes});
        return bytes.len;
    }

    pub fn writeAll(self: StdoutWriter, bytes: []const u8) Error!void {
        _ = try self.write(bytes);
    }

    pub fn print(self: StdoutWriter, comptime format: []const u8, args: anytype) Error!void {
        _ = self;
        std.debug.print(format, args);
    }

    pub fn writer(self: StdoutWriter) Writer {
        return .{ .context = self };
    }
};

const StderrWriter = struct {
    pub const Error = error{};
    pub const Writer = std.io.Writer(StderrWriter, Error, write);

    pub fn write(self: StderrWriter, bytes: []const u8) Error!usize {
        _ = self;
        std.debug.print("{s}", .{bytes});
        return bytes.len;
    }

    pub fn writeAll(self: StderrWriter, bytes: []const u8) Error!void {
        _ = try self.write(bytes);
    }

    pub fn print(self: StderrWriter, comptime format: []const u8, args: anytype) Error!void {
        _ = self;
        std.debug.print(format, args);
    }

    pub fn writer(self: StderrWriter) Writer {
        return .{ .context = self };
    }
};

pub const Command = enum {
    workflow_list,
    workflow_run,
    workflow_lint,
    run_list,
    run_view,
    run_watch,
    run_cancel,
    prompt_preview,
    prompt_test,
    help,
    unknown,
    // SSH helpers (external-sshd integration)
    ssh_authorized_keys,
    ssh_serv,
};

pub const CliArgs = struct {
    command: Command,
    args: []const []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *CliArgs) void {
        _ = self;
        // Args are owned by process.argsAlloc, freed by caller
    }
};

/// Parse CLI arguments and determine command
pub fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) !CliArgs {
    if (args.len < 2) {
        return CliArgs{
            .command = .help,
            .args = args,
            .allocator = allocator,
        };
    }

    const subcommand = args[1];
    const rest = if (args.len > 2) args[2..] else args[0..0];

    const command: Command = blk: {
        if (std.mem.eql(u8, subcommand, "workflow")) {
            if (rest.len == 0) break :blk .help;
            const verb = rest[0];
            if (std.mem.eql(u8, verb, "list")) break :blk .workflow_list;
            if (std.mem.eql(u8, verb, "run")) break :blk .workflow_run;
            if (std.mem.eql(u8, verb, "lint")) break :blk .workflow_lint;
            break :blk .unknown;
        } else if (std.mem.eql(u8, subcommand, "run")) {
            if (rest.len == 0) break :blk .help;
            const verb = rest[0];
            if (std.mem.eql(u8, verb, "list")) break :blk .run_list;
            if (std.mem.eql(u8, verb, "view")) break :blk .run_view;
            if (std.mem.eql(u8, verb, "watch")) break :blk .run_watch;
            if (std.mem.eql(u8, verb, "cancel")) break :blk .run_cancel;
            break :blk .unknown;
        } else if (std.mem.eql(u8, subcommand, "prompt")) {
            if (rest.len == 0) break :blk .help;
            const verb = rest[0];
            if (std.mem.eql(u8, verb, "preview")) break :blk .prompt_preview;
            if (std.mem.eql(u8, verb, "test")) break :blk .prompt_test;
            break :blk .unknown;
        } else if (std.mem.eql(u8, subcommand, "ssh")) {
            // Subcommands: authorized-keys <username>, serv key-<id>
            if (rest.len == 0) break :blk .help;
            const verb = rest[0];
            if (std.mem.eql(u8, verb, "authorized-keys")) break :blk .ssh_authorized_keys;
            if (std.mem.eql(u8, verb, "serv")) break :blk .ssh_serv;
            break :blk .unknown;
        } else if (std.mem.eql(u8, subcommand, "help") or std.mem.eql(u8, subcommand, "--help") or std.mem.eql(u8, subcommand, "-h")) {
            break :blk .help;
        } else {
            break :blk .unknown;
        }
    };

    return CliArgs{
        .command = command,
        .args = rest,
        .allocator = allocator,
    };
}

/// Print help message
pub fn printHelp(writer: anytype) !void {
    try writer.writeAll(
        \\Plue CLI - Workflow and Prompt Management
        \\
        \\Usage:
        \\  plue <command> [options]
        \\
        \\Commands:
        \\  Workflow Management:
        \\    workflow list                   List all workflows in repository
        \\    workflow run <name>             Run workflow manually
        \\    workflow run <name> --input k=v Run with manual inputs
        \\    workflow lint                   Lint .py and .prompt.md files
        \\
        \\  Run Management:
        \\    run list                        List recent workflow runs
        \\    run view <run-id>               View run details and logs
        \\    run watch <run-id>              Watch live run (SSE stream)
        \\    run cancel <run-id>             Cancel running workflow
        \\
        \\  Prompt Development:
        \\    prompt preview <file>           Render prompt with sample inputs
        \\    prompt test <file>              Test prompt execution
        \\
        \\  General:
        \\    help                            Show this help message
        \\
        \\Examples:
        \\  plue workflow list
        \\  plue workflow run ci
        \\  plue run watch 123
        \\  plue prompt preview .plue/prompts/CodeReview.prompt.md
        \\
        \\For more information, see: docs/workflows-prd.md
        \\
    );
}

/// Execute a CLI command
pub fn execute(allocator: std.mem.Allocator, cli_args: CliArgs) !void {
    // Note: Using std.debug.print for simplicity due to Zig 0.15 stdio API changes
    // In production, we'd properly handle stdout/stderr file descriptors
    const stdout = StdoutWriter{};
    const stderr = StderrWriter{};

    switch (cli_args.command) {
        .help => {
            try printHelp(stdout);
            return;
        },
        .unknown => {
            try stderr.writeAll("Error: Unknown command\n\n");
            try printHelp(stderr);
            return error.UnknownCommand;
        },
        .workflow_list => {
            try executeWorkflowList(allocator, stdout);
        },
        .workflow_run => {
            if (cli_args.args.len < 2) {
                try stderr.writeAll("Error: workflow name required\n");
                try stderr.writeAll("Usage: plue workflow run <name>\n");
                return error.MissingArgument;
            }
            const workflow_name = cli_args.args[1];
            try executeWorkflowRun(allocator, stdout, workflow_name);
        },
        .workflow_lint => {
            try executeWorkflowLint(allocator, stdout);
        },
        .run_list => {
            try executeRunList(allocator, stdout);
        },
        .run_view => {
            if (cli_args.args.len < 2) {
                try stderr.writeAll("Error: run ID required\n");
                try stderr.writeAll("Usage: plue run view <run-id>\n");
                return error.MissingArgument;
            }
            const run_id = try std.fmt.parseInt(i32, cli_args.args[1], 10);
            try executeRunView(allocator, stdout, run_id);
        },
        .run_watch => {
            if (cli_args.args.len < 2) {
                try stderr.writeAll("Error: run ID required\n");
                try stderr.writeAll("Usage: plue run watch <run-id>\n");
                return error.MissingArgument;
            }
            const run_id = try std.fmt.parseInt(i32, cli_args.args[1], 10);
            try executeRunWatch(allocator, stdout, run_id);
        },
        .run_cancel => {
            if (cli_args.args.len < 2) {
                try stderr.writeAll("Error: run ID required\n");
                try stderr.writeAll("Usage: plue run cancel <run-id>\n");
                return error.MissingArgument;
            }
            const run_id = try std.fmt.parseInt(i32, cli_args.args[1], 10);
            try executeRunCancel(allocator, stdout, run_id);
        },
        .prompt_preview => {
            if (cli_args.args.len < 2) {
                try stderr.writeAll("Error: prompt file required\n");
                try stderr.writeAll("Usage: plue prompt preview <file>\n");
                return error.MissingArgument;
            }
            const file_path = cli_args.args[1];
            try executePromptPreview(allocator, stdout, file_path);
        },
        .prompt_test => {
            if (cli_args.args.len < 2) {
                try stderr.writeAll("Error: prompt file required\n");
                try stderr.writeAll("Usage: plue prompt test <file>\n");
                return error.MissingArgument;
            }
            const file_path = cli_args.args[1];
            try executePromptTest(allocator, stdout, file_path);
        },
        .ssh_authorized_keys => {
            // Usage: plue ssh authorized-keys <username>
            if (cli_args.args.len < 2) {
                try stderr.writeAll("Error: username required\n");
                try stderr.writeAll("Usage: plue ssh authorized-keys <username>\n");
                return error.MissingArgument;
            }
            const username = cli_args.args[1];
            try executeSshAuthorizedKeys(allocator, stdout, username);
        },
        .ssh_serv => {
            // Usage: plue ssh serv key-<id>
            const key_ctx: []const u8 = if (cli_args.args.len >= 2) cli_args.args[1] else "";
            try executeSshServ(allocator, stdout, key_ctx);
        },
    }
}

// ============================================================================
// Command Implementations
// ============================================================================

fn executeWorkflowList(allocator: std.mem.Allocator, writer: anytype) !void {
    // Scan .plue/workflows/ directory for workflow files
    const workflows_dir = ".plue/workflows";

    var dir = std.fs.cwd().openDir(workflows_dir, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound) {
            try writer.writeAll("No workflows found. Create workflows in .plue/workflows/\n");
            return;
        }
        return err;
    };
    defer dir.close();

    try writer.writeAll("Workflows:\n");

    var iter = dir.iterate();
    var count: usize = 0;
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".py")) continue;

        // Parse the workflow to get its name
        const content = try dir.readFileAlloc(allocator, entry.name, 1024 * 1024);
        defer allocator.free(content);

        var evaluator = workflows.Evaluator.init(allocator);
        var result = evaluator.evaluateSource(content, entry.name) catch |err| {
            try writer.print("  {s} (parse error: {s})\n", .{ entry.name, @errorName(err) });
            continue;
        };
        defer result.deinit(allocator);

        if (result.workflows.len > 0) {
            const workflow = result.workflows[0];
            try writer.print("  {s} - {s} ({d} steps, {d} triggers)\n", .{
                workflow.name,
                entry.name,
                workflow.steps.len,
                workflow.triggers.len,
            });
            count += 1;
        }
    }

    if (count == 0) {
        try writer.writeAll("  (no valid workflows found)\n");
    }
}

fn executeWorkflowRun(allocator: std.mem.Allocator, writer: anytype, workflow_name: []const u8) !void {
    try writer.print("Running workflow: {s}\n", .{workflow_name});
    try writer.writeAll("Note: This CLI is currently a stub. To run workflows:\n");
    try writer.writeAll("  1. Start the server: zig build run\n");
    try writer.writeAll("  2. Use the API: POST /api/workflows/run\n");
    try writer.writeAll("  3. Or use the web UI at http://localhost:4000\n");
    _ = allocator;
}

fn executeWorkflowLint(allocator: std.mem.Allocator, writer: anytype) !void {
    const workflows_dir = ".plue/workflows";
    const prompts_dir = ".plue/prompts";

    var total_files: usize = 0;
    var total_errors: usize = 0;

    // Lint workflow files
    try writer.writeAll("Linting workflows...\n");
    var dir = std.fs.cwd().openDir(workflows_dir, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound) {
            try writer.writeAll("  (no workflows directory found)\n");
        } else {
            return err;
        }

        // Skip to prompts section
        try writer.writeAll("\nLinting prompts...\n");
        var prompts_dir_handle = std.fs.cwd().openDir(prompts_dir, .{ .iterate = true }) catch |prompt_err| {
            if (prompt_err == error.FileNotFound) {
                try writer.writeAll("  (no prompts directory found)\n");
            } else {
                return prompt_err;
            }
            try writer.print("\nLint complete: {d} files, {d} errors\n", .{ total_files, total_errors });
            return if (total_errors > 0) error.LintFailed else {};
        };
        defer prompts_dir_handle.close();

        var prompt_iter = prompts_dir_handle.iterate();
        while (try prompt_iter.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".prompt.md")) continue;

            total_files += 1;

            const file_path = try std.fs.path.join(allocator, &[_][]const u8{ prompts_dir, entry.name });
            defer allocator.free(file_path);

            var prompt_def = workflows.prompt.parsePromptFile(allocator, file_path) catch |parse_err| {
                try writer.print("  ✗ {s}: {s}\n", .{ entry.name, @errorName(parse_err) });
                total_errors += 1;
                continue;
            };
            defer prompt_def.deinit();

            try writer.print("  ✓ {s} ({s})\n", .{ entry.name, prompt_def.name });
        }

        try writer.print("\nLint complete: {d} files, {d} errors\n", .{ total_files, total_errors });
        return if (total_errors > 0) error.LintFailed else {};
    };
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".py")) continue;

        total_files += 1;
        const content = try dir.readFileAlloc(allocator, entry.name, 1024 * 1024);
        defer allocator.free(content);

        var evaluator = workflows.Evaluator.init(allocator);
        var result = evaluator.evaluateSource(content, entry.name) catch |err| {
            try writer.print("  ✗ {s}: {s}\n", .{ entry.name, @errorName(err) });
            total_errors += 1;
            continue;
        };
        defer result.deinit(allocator);

        // Validate each workflow
        for (result.workflows) |workflow| {
            var validation = try workflows.validateWorkflow(allocator, &workflow);
            defer validation.deinit();

            if (!validation.valid) {
                try writer.print("  ✗ {s} ({s}): validation failed\n", .{ entry.name, workflow.name });
                for (validation.errors) |issue| {
                    try writer.print("      {s}\n", .{issue.message});
                }
                total_errors += validation.errors.len;
            } else {
                try writer.print("  ✓ {s} ({s})\n", .{ entry.name, workflow.name });
            }
        }
    }

    try writer.print("\nLint complete: {d} files, {d} errors\n", .{ total_files, total_errors });
}

fn executeRunList(_: std.mem.Allocator, writer: anytype) !void {
    try writer.writeAll("Recent workflow runs:\n");
    try writer.writeAll("Note: This CLI is currently a stub. To view runs:\n");
    try writer.writeAll("  1. Use the API: GET /api/workflows/runs\n");
    try writer.writeAll("  2. Or use the web UI at http://localhost:4000\n");
}

fn executeRunView(_: std.mem.Allocator, writer: anytype, run_id: i32) !void {
    try writer.print("Viewing run {d}:\n", .{run_id});
    try writer.writeAll("Note: This CLI is currently a stub. To view run details:\n");
    try writer.writeAll("  1. Use the API: GET /api/workflows/runs/{d}\n");
    try writer.writeAll("  2. Or use the web UI at http://localhost:4000/workflows/runs/{d}\n");
}

fn executeRunWatch(_: std.mem.Allocator, writer: anytype, run_id: i32) !void {
    try writer.print("Watching run {d}...\n", .{run_id});
    try writer.writeAll("Note: This CLI is currently a stub. To watch a live run:\n");
    try writer.writeAll("  1. Use SSE: GET /api/workflows/runs/{d}/stream\n");
    try writer.writeAll("  2. Or use the web UI at http://localhost:4000/workflows/runs/{d}\n");
}

fn executeRunCancel(_: std.mem.Allocator, writer: anytype, run_id: i32) !void {
    try writer.print("Cancelling run {d}...\n", .{run_id});
    try writer.writeAll("Note: This CLI is currently a stub. To cancel a run:\n");
    try writer.writeAll("  1. Use the API: POST /api/workflows/runs/{d}/cancel\n");
    try writer.writeAll("  2. Or use the web UI at http://localhost:4000/workflows/runs/{d}\n");
}

fn executePromptPreview(allocator: std.mem.Allocator, writer: anytype, file_path: []const u8) !void {
    try writer.print("Previewing prompt: {s}\n\n", .{file_path});

    var prompt_def = try workflows.prompt.parsePromptFile(allocator, file_path);
    defer prompt_def.deinit();

    try writer.print("Name: {s}\n", .{prompt_def.name});
    try writer.print("Client: {s}\n", .{prompt_def.client});
    try writer.print("Type: {s}\n", .{prompt_def.prompt_type});
    try writer.print("Max turns: {d}\n", .{prompt_def.max_turns});

    try writer.writeAll("\nTemplate body:\n");
    try writer.writeAll("---\n");
    try writer.print("{s}\n", .{prompt_def.body_template});
    try writer.writeAll("---\n");
}

fn executePromptTest(allocator: std.mem.Allocator, writer: anytype, file_path: []const u8) !void {
    try writer.print("Testing prompt: {s}\n", .{file_path});
    try writer.writeAll("Note: This CLI is currently a stub. To test a prompt:\n");
    try writer.writeAll("  1. Use the API: POST /api/prompts/test\n");
    try writer.writeAll("  2. Or use the web UI prompt editor\n");
    _ = allocator;
}

// =============================================================================
// SSH: Authorized Keys Command
// =============================================================================

fn connectDb(allocator: std.mem.Allocator) !*db.Pool {
    const url = std.posix.getenv("DATABASE_URL") orelse "postgresql://postgres:password@localhost:54321/plue?sslmode=disable";
    const uri = try std.Uri.parse(url);
    const pool = try allocator.create(db.Pool);
    pool.* = try db.Pool.initUri(allocator, uri, .{ .size = 4, .timeout = 10_000 });
    return pool;
}

fn executeSshAuthorizedKeys(allocator: std.mem.Allocator, writer: anytype, username: []const u8) !void {
    // Allow only the configured login user. Precedence:
    // SSH_AUTHORIZED_KEYS_USER > SSH_LOGIN_USER > "git"
    const allowed_user = blk: {
        if (std.posix.getenv("SSH_AUTHORIZED_KEYS_USER")) |v| break :blk v;
        if (std.posix.getenv("SSH_LOGIN_USER")) |v| break :blk v;
        break :blk "git";
    };
    if (!std.mem.eql(u8, username, allowed_user)) return;

    var pool = try connectDb(allocator);
    defer pool.deinit();

    // Emit one line per active key with tight forced options and ForcedCommand to plue ssh serv key-<id>
    // Note: we intentionally exclude users with prohibit_login = true
    var conn = try pool.acquire();
    defer conn.release();

    var result = try conn.query(
        \\SELECT k.id, k.public_key
        \\FROM ssh_keys k
        \\JOIN users u ON u.id = k.user_id
        \\WHERE u.is_active = true
        \\  AND u.prohibit_login = false
        \\ORDER BY k.id
    , .{});
    defer result.deinit();

    const plue_bin = std.posix.getenv("PLUE_BIN");
    // Arena for small string work
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const forced_raw = if (plue_bin) |p| p else "plue";

    // Escape for inclusion inside a double-quoted authorized_keys command="..."
    const forced = try escapeForDoubleQuotes(aa, forced_raw);

    while (try result.next()) |row| {
        const key_id = row.get(i64, 0);
        const public_key = row.get([]const u8, 1);

        try writer.print(
            "command=\"{s} ssh serv key-{d}\",restrict,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,no-user-rc {s}\n",
            .{ forced, key_id, public_key },
        );
    }
}

// =============================================================================
// SSH: Serv (ForcedCommand) - Authorization + Exec git-*-pack
// =============================================================================

const GitOp = enum { upload_pack, receive_pack, upload_archive, lfs_download, lfs_upload };

fn parseOriginalCommand(cmd: []const u8) !struct { op: GitOp, repo: []const u8 } {
    // Expected forms:
    //   git-upload-pack '/owner/repo.git'
    //   git-receive-pack "/owner/repo.git"
    //   git-lfs-authenticate '/owner/repo.git' (download|upload)
    var it = std.mem.tokenizeScalar(u8, cmd, ' ');
    const prog = it.next() orelse return error.InvalidCommand;

    if (std.mem.eql(u8, prog, "git-upload-pack") or std.mem.eql(u8, prog, "git-receive-pack")) {
        const arg = std.mem.trim(u8, it.next() orelse return error.InvalidCommand, "'\" ");
        if (std.mem.eql(u8, prog, "git-upload-pack")) return .{ .op = .upload_pack, .repo = arg };
        return .{ .op = .receive_pack, .repo = arg };
    }

    if (std.mem.eql(u8, prog, "git-lfs-authenticate")) {
        const repo = std.mem.trim(u8, it.next() orelse return error.InvalidCommand, "'\" ");
        const mode = it.next() orelse return error.InvalidCommand;
        if (std.mem.eql(u8, mode, "download")) return .{ .op = .lfs_download, .repo = repo };
        if (std.mem.eql(u8, mode, "upload")) return .{ .op = .lfs_upload, .repo = repo };
        return error.InvalidCommand;
    }

    return error.UnsupportedCommand;
}

fn startsWithDir(parent: []const u8, child: []const u8) bool {
    if (!std.mem.startsWith(u8, child, parent)) return false;
    if (child.len == parent.len) return true;
    return child[parent.len] == '/';
}

fn getClientIp() []const u8 {
    // Prefer real client IP propagated by the bridge; fallback to SSH_CONNECTION parsing
    if (std.posix.getenv("PLUE_REAL_CLIENT_IP")) |ip| {
        if (ip.len > 0) return ip;
    }
    const sc = std.posix.getenv("SSH_CONNECTION") orelse "";
    var it = std.mem.tokenizeScalar(u8, sc, ' ');
    return it.next() orelse sc;
}

fn executeSshServ(allocator: std.mem.Allocator, writer: anytype, key_ctx: []const u8) !void {
    // Extract key id from key-<id>
    var key_id: i64 = -1;
    if (std.mem.startsWith(u8, key_ctx, "key-")) {
        key_id = std.fmt.parseInt(i64, key_ctx[4..], 10) catch -1;
    }
    if (key_id <= 0) return error.InvalidKeyContext;

    const orig = std.posix.getenv("SSH_ORIGINAL_COMMAND") orelse return error.MissingOriginalCommand;
    const parsed = parseOriginalCommand(orig) catch {
        const ip_only = getClientIp();
        ssh_security.logCommandRejected(ip_only, "git", orig, "invalid command");
        return error.InvalidCommand;
    };

    // Normalize repo path: strip leading slashes and .git suffix
    var repo_path = parsed.repo;
    while (repo_path.len > 0 and repo_path[0] == '/') repo_path = repo_path[1..];
    if (std.mem.endsWith(u8, repo_path, ".git")) repo_path = repo_path[0 .. repo_path.len - 4];

    // Expect exactly owner/repo
    var parts = std.mem.splitScalar(u8, repo_path, '/');
    const owner = parts.next() orelse return error.InvalidRepoPath;
    const name = parts.next() orelse return error.InvalidRepoPath;
    if (parts.next()) |_| return error.InvalidRepoPath; // too many segments

    // DB lookups
    var pool = try connectDb(allocator);
    defer pool.deinit();

    // 1) Resolve user who owns the key and ensure active/prohibit_login=false
    var conn = try pool.acquire();
    defer conn.release();

    var row = try conn.row(
        \\SELECT u.id::bigint, u.username, u.is_active, u.prohibit_login
        \\FROM users u
        \\JOIN ssh_keys k ON k.user_id = u.id
        \\WHERE k.id = $1
    , .{key_id});
    if (row == null) return error.KeyNotFound;
    const key_user_id = row.?.get(i64, 0);
    const key_user_active = row.?.get(bool, 2);
    const key_user_prohibit = row.?.get(bool, 3);
    if (!key_user_active or key_user_prohibit) return error.UserNotAllowed;

    // 2) Resolve repository owner/name and visibility
    const repo = try db.getRepositoryByUserAndName(pool, owner, name) orelse return error.RepoNotFound;

    // 3) Authorization
    const op = parsed.op;
    // Read rules: allowed if repo.is_public OR repo owner is key owner
    const can_read = repo.is_public or (repo.user_id == key_user_id);
    // Write rules: only owner for now (no collaborators yet)
    const can_write = (repo.user_id == key_user_id);
    const allowed = switch (op) {
        .upload_pack => can_read,
        .receive_pack => can_write,
        .lfs_download => can_read,
        .lfs_upload => can_write,
    };
    // Log decision
    const ip_only = getClientIp();
    std.log.info("ssh-serv key={d} client={s} repo={s}/{s} op={s} allow={}", .{
        key_id, ip_only, owner, name,
        switch (op) {
            .upload_pack => "upload-pack",
            .receive_pack => "receive-pack",
            .lfs_download => "lfs-download",
            .lfs_upload => "lfs-upload",
        },
        allowed,
    });
    if (!allowed) {
        ssh_security.logCommandRejected(ip_only, "git", orig, "access denied");
        return error.AccessDenied;
    }

    // 4) Resolve filesystem path and prevent traversal
    const repos_dir = std.posix.getenv("PLUE_REPOS_DIR") orelse "/var/lib/plue/repos";
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const target_rel = try std.fs.path.join(aa, &.{ owner, name });
    const target = try std.fs.path.join(aa, &.{ repos_dir, target_rel });

    const canon_repos = try std.fs.cwd().realpathAlloc(aa, repos_dir);
    const canon_target = std.fs.cwd().realpathAlloc(aa, target) catch return error.RepoPathInvalid;
    defer aa.free(canon_repos);
    defer aa.free(canon_target);
    if (!startsWithDir(canon_repos, canon_target)) return error.RepoPathTraversal;

    // 5) Handle LFS authenticate or exec git-*-pack
    if (op == .lfs_download or op == .lfs_upload) {
        // Construct LFS endpoint and headers
        var arena_lfs = std.heap.ArenaAllocator.init(allocator);
        defer arena_lfs.deinit();
        const aalfs = arena_lfs.allocator();

        const explicit_lfs_base = std.posix.getenv("PLUE_LFS_URL");
        const http_base = std.posix.getenv("PLUE_HTTP_URL") orelse "http://localhost:4000";

        const href = if (explicit_lfs_base) |b|
            try std.fmt.allocPrint(aalfs, "{s}/{s}/{s}.git/info/lfs", .{ b, owner, name })
        else
            try std.fmt.allocPrint(aalfs, "{s}/{s}/{s}.git/info/lfs", .{ http_base, owner, name });

        const token = std.posix.getenv("PLUE_LFS_TOKEN");

        if (token) |t| {
            try writer.print(
                "{\"href\":\"{s}\",\"header\":{\"Authorization\":\"Bearer {s}\"}}\n",
                .{ href, t },
            );
        } else {
            try writer.print("{\"href\":\"{s}\",\"header\":{}}\n", .{ href });
        }

        ssh_security.logCommandExecuted(ip_only, "git-lfs", "git-lfs-authenticate");
        ssh_security.logSessionClosed(ip_only, "git-lfs", 0);
        return;
    }

    // Exec git-*-pack with inherited stdio
    const git_upload = std.posix.getenv("PLUE_GIT_UPLOAD_PACK") orelse "/usr/bin/git-upload-pack";
    const git_receive = std.posix.getenv("PLUE_GIT_RECEIVE_PACK") orelse "/usr/bin/git-receive-pack";
    const bin = switch (op) {
        .upload_pack => git_upload,
        .receive_pack => git_receive,
        .lfs_download => git_upload, // unreachable due to early return
        .lfs_upload => git_receive,
    };

    var child = std.process.Child.init(&.{ bin, canon_target }, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    const term = try child.spawnAndWait();

    switch (term) {
        .Exited => |code| {
            // On successful push, trigger JJ sync via HTTP if configured
            if (code == 0 and op == .receive_pack) {
                if (std.posix.getenv("PLUE_API_URL")) |api| {
                    var http_child = std.process.Child.init(
                        &.{ "curl", "-s", "-f", "-m", "5", try std.fmt.allocPrint(aa, "{s}/api/watcher/sync/{s}/{s}", .{ api, owner, name }) },
                        allocator,
                    );
                    http_child.stdin_behavior = .Ignore;
                    http_child.stdout_behavior = .Ignore;
                    http_child.stderr_behavior = .Ignore;
                    _ = http_child.spawnAndWait() catch {};
                }
            }
            // Propagate exit code and log
            if (code == 0) {
                const cmd_name = switch (op) { .upload_pack => "git-upload-pack", .receive_pack => "git-receive-pack" };
                ssh_security.logCommandExecuted(ip_only, "git", cmd_name);
                ssh_security.logSessionClosed(ip_only, "git", 0);
            }
            if (code != 0) return error.ExecFailed;
        },
        else => return error.ExecFailed,
    }
}

// ============================================================================
// Tests
// ============================================================================

test "parseArgs - help" {
    const allocator = std.testing.allocator;
    const args = &[_][]const u8{ "plue", "help" };
    const result = try parseArgs(allocator, args);
    try std.testing.expectEqual(Command.help, result.command);
}

test "parseArgs - workflow list" {
    const allocator = std.testing.allocator;
    const args = &[_][]const u8{ "plue", "workflow", "list" };
    const result = try parseArgs(allocator, args);
    try std.testing.expectEqual(Command.workflow_list, result.command);
}

test "parseArgs - workflow run" {
    const allocator = std.testing.allocator;
    const args = &[_][]const u8{ "plue", "workflow", "run", "ci" };
    const result = try parseArgs(allocator, args);
    try std.testing.expectEqual(Command.workflow_run, result.command);
    try std.testing.expectEqual(@as(usize, 2), result.args.len);
    try std.testing.expectEqualStrings("ci", result.args[1]);
}

test "parseArgs - run view" {
    const allocator = std.testing.allocator;
    const args = &[_][]const u8{ "plue", "run", "view", "123" };
    const result = try parseArgs(allocator, args);
    try std.testing.expectEqual(Command.run_view, result.command);
}

test "parseArgs - prompt preview" {
    const allocator = std.testing.allocator;
    const args = &[_][]const u8{ "plue", "prompt", "preview", "test.prompt.md" };
    const result = try parseArgs(allocator, args);
    try std.testing.expectEqual(Command.prompt_preview, result.command);
}

test "parseArgs - unknown command" {
    const allocator = std.testing.allocator;
    const args = &[_][]const u8{ "plue", "foo" };
    const result = try parseArgs(allocator, args);
    try std.testing.expectEqual(Command.unknown, result.command);
}

test "parseOriginalCommand - upload" {
    const p = try parseOriginalCommand("git-upload-pack '/alice/repo.git'");
    try std.testing.expectEqual(GitOp.upload_pack, p.op);
    try std.testing.expectEqualStrings("/alice/repo.git", p.repo);
}

test "parseOriginalCommand - receive double quotes" {
    const p = try parseOriginalCommand("git-receive-pack \"/a/b.git\"");
    try std.testing.expectEqual(GitOp.receive_pack, p.op);
    try std.testing.expectEqualStrings("/a/b.git", p.repo);
}

test "parseOriginalCommand - lfs download" {
    const p = try parseOriginalCommand("git-lfs-authenticate '/ow/n.git' download");
    try std.testing.expectEqual(GitOp.lfs_download, p.op);
    try std.testing.expectEqualStrings("/ow/n.git", p.repo);
}

test "parseOriginalCommand - lfs upload" {
    const p = try parseOriginalCommand("git-lfs-authenticate '/ow/n.git' upload");
    try std.testing.expectEqual(GitOp.lfs_upload, p.op);
}

test "parseOriginalCommand - invalid" {
    try std.testing.expectError(error.InvalidCommand, parseOriginalCommand("git-upload-pack"));
}

test "parseOriginalCommand - unsupported" {
    try std.testing.expectError(error.UnsupportedCommand, parseOriginalCommand("echo hi"));
}

// ---- helpers ----
fn escapeForDoubleQuotes(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var extra: usize = 0;
    for (s) |c| {
        if (c == '"' or c == '\\') {
            extra += 1;
        }
    }
    if (extra == 0) return allocator.dupe(u8, s);
    var out = try allocator.alloc(u8, s.len + extra);
    var j: usize = 0;
    for (s) |c| {
        if (c == '"' or c == '\\') {
            out[j] = '\\';
            j += 1;
        }
        out[j] = c; j += 1;
    }
    return out;
}
