const std = @import("std");
const rate_limit = @import("rate_limit.zig");

pub const Error = error{
    SshdNotFound,
    SpawnFailed,
    MissingAuthorizedKeysCommand,
    ScriptNotExecutable,
    NotPrivileged,
    UserNotFound,
    AuthorizedKeysCommandUnsafe,
    HostKeyUnreadable,
};

const log = std.log.scoped(.sshd_bridge);

fn makePath(allocator: std.mem.Allocator, a: []const u8, b: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ a, b });
}

fn tailBufferAppend(buf: *std.ArrayList(u8), data: []const u8, max: usize) !void {
    if (data.len == 0) return;
    if (buf.items.len + data.len <= max) {
        try buf.appendSlice(data);
        return;
    }
    const keep = @min(max, data.len + buf.items.len);
    const need_drop = buf.items.len + data.len - keep;
    if (need_drop > 0 and need_drop <= buf.items.len) {
        std.mem.copy(u8, buf.items[0..], buf.items[need_drop..]);
        try buf.resize(buf.items.len - need_drop);
    } else if (need_drop >= buf.items.len) {
        try buf.resize(0);
    }
    try buf.appendSlice(data);
    if (buf.items.len > max) try buf.resize(max);
}

fn isAbsolutePath(p: []const u8) bool {
    // Accept both Unix absolute and Windows drive letters for portability
    return (p.len > 0 and p[0] == '/') or (p.len >= 3 and std.ascii.isAlpha(p[0]) and p[1] == ':' and (p[2] == '/' or p[2] == '\\'));
}

fn which(allocator: std.mem.Allocator, exe: []const u8) bool {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    const cmd = std.fmt.allocPrint(aa, "command -v {s} >/dev/null 2>&1", .{exe}) catch return false;
    var child = std.process.Child.init(&.{ "sh", "-c", cmd }, aa);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    const term = child.spawnAndWait() catch return false;
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

fn userExists(allocator: std.mem.Allocator, user: []const u8) bool {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    const cmd = std.fmt.allocPrint(aa, "id -u {s} >/dev/null 2>&1", .{user}) catch return false;
    var child = std.process.Child.init(&.{ "sh", "-c", cmd }, aa);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    const term = child.spawnAndWait() catch return false;
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

fn runningAsUser(allocator: std.mem.Allocator, user: []const u8) bool {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    const cmd = "id -un";
    var child = std.process.Child.init(&.{ "sh", "-c", cmd }, aa);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    if (child.spawn()) |_| {} else |_| return false;
    var buf: [128]u8 = undefined;
    const n = child.stdout.?.reader().read(&buf) catch 0;
    const term = child.wait() catch return false;
    if (switch (term) { .Exited => |code| code != 0, else => true }) return false;
    const got = std.mem.trimRight(u8, buf[0..n], "\r\n \t");
    return std.mem.eql(u8, got, user);
}

pub fn preflightCheck(
    allocator: std.mem.Allocator,
    scripts_dir: []const u8,
    hostkey_rsa: []const u8,
    hostkey_ed25519: []const u8,
    login_user: []const u8,
    authorized_keys_user: []const u8,
) !void {
    // Check sshd binary
    if (!which(allocator, "sshd")) return Error.SshdNotFound;

    // Check host keys exist and are readable by the effective user.
    // Missing keys are auto-generated later, but unreadable keys should fail fast.
    if (std.fs.cwd().access(hostkey_rsa, .{})) {
        // verify readability by effective user
        _ = std.fs.cwd().openFile(hostkey_rsa, .{ .mode = .read_only }) catch |e| {
            log.err("host RSA key not readable at {s}: {}", .{ hostkey_rsa, e });
            return Error.HostKeyUnreadable;
        };
    } else |_| {
        log.warn("host RSA key missing at {s}; will attempt auto-generate at runtime", .{hostkey_rsa});
    }
    if (std.fs.cwd().access(hostkey_ed25519, .{})) {
        _ = std.fs.cwd().openFile(hostkey_ed25519, .{ .mode = .read_only }) catch |e| {
            log.err("host Ed25519 key not readable at {s}: {}", .{ hostkey_ed25519, e });
            return Error.HostKeyUnreadable;
        };
    } else |_| {
        log.warn("host Ed25519 key missing at {s}; will attempt auto-generate at runtime", .{hostkey_ed25519});
    }

    // Check AuthorizedKeysCommand script
    const script_rel = try makePath(std.heap.page_allocator, scripts_dir, "authorized_keys_command.sh");
    defer std.heap.page_allocator.free(script_rel);
    if (std.fs.cwd().access(script_rel, .{})) {} else |_| return Error.MissingAuthorizedKeysCommand;
    // Resolve absolute path to satisfy sshd absolute-path requirement
    const script_path = std.fs.cwd().realpathAlloc(std.heap.page_allocator, script_rel) catch |e| {
        log.err("failed to resolve absolute path for AuthorizedKeysCommand {s}: {}", .{ script_rel, e });
        return Error.MissingAuthorizedKeysCommand;
    };
    defer std.heap.page_allocator.free(script_path);
    if (!isAbsolutePath(script_path)) {
        log.err("AuthorizedKeysCommand must be an absolute path: {s}", .{script_path});
        return Error.AuthorizedKeysCommandUnsafe;
    }
    var __f = std.fs.cwd().openFile(script_path, .{ .mode = .read_only }) catch |__e| {
        return Error.MissingAuthorizedKeysCommand;
    };
    defer __f.close();
    var __st: std.posix.Stat = undefined;
    _ = std.posix.fstat(__f.handle, &__st) catch return Error.MissingAuthorizedKeysCommand;
    if ((__st.mode & 0o111) == 0) {
        log.err("AuthorizedKeysCommand not executable: {s}", .{script_path});
        return Error.ScriptNotExecutable;
    }
    // Enforce root ownership and non-writable by group/other per sshd_config(5)
    if (__st.uid != 0 or (__st.mode & 0o022) != 0) {
        log.err(
            "AuthorizedKeysCommand must be root-owned and not group/world-writable: {s} (uid={d}, mode=0o{o})",
            .{ script_path, __st.uid, __st.mode },
        );
        return Error.AuthorizedKeysCommandUnsafe;
    }

    // Validate configured users exist (runtime must run as root or as login_user)
    if (!userExists(allocator, login_user)) return Error.UserNotFound;
    if (!std.mem.eql(u8, login_user, authorized_keys_user)) {
        if (!userExists(allocator, authorized_keys_user)) return Error.UserNotFound;
    }

    const euid = std.posix.geteuid();
    if (euid != 0 and !runningAsUser(allocator, login_user)) {
        log.err("sshd inetd requires root or user '{s}' (euid={d})", .{ login_user, euid });
        return Error.NotPrivileged;
    }

    // Check plue binary (optional; warn only)
    if (std.posix.getenv("PLUE_BIN")) |p| {
        _ = p; // Assume path is valid; runtime errors will be visible in sshd logs
    } else if (!which(allocator, "plue")) {
        log.warn("plue binary not found in PATH and PLUE_BIN not set; authorized-keys may fail", .{});
    }
}

/// Spawn OpenSSH sshd (inetd mode) and proxy stdio to client_stream.
/// Writes any prebuffer bytes to sshd stdin before proxying.
pub fn spawnSshdBridge(
    allocator: std.mem.Allocator,
    client_stream: std.net.Stream,
    client_ip: []const u8,
    prebuffer: []const u8,
    hostkey_rsa: []const u8,
    hostkey_ed25519: []const u8,
    scripts_dir_opt: []const u8,
    login_user: []const u8,
    authorized_keys_user: []const u8,
    rate_limiter: *rate_limit.RateLimiter,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    // Resolve script dir
    const scripts_dir = blk: {
        if (scripts_dir_opt.len > 0) break :blk scripts_dir_opt;
        if (std.posix.getenv("PLUE_SCRIPTS_DIR")) |p| break :blk p;
        break :blk "server/scripts";
    };
    const auth_keys_cmd_rel = try makePath(aa, scripts_dir, "authorized_keys_command.sh");
    // Resolve to absolute path for sshd
    const auth_keys_cmd = std.fs.cwd().realpathAlloc(aa, auth_keys_cmd_rel) catch auth_keys_cmd_rel;

    // Privilege model: must run as root (preferred) or as the target login user
    const euid = std.posix.geteuid();
    if (euid != 0) {
        if (!runningAsUser(allocator, login_user)) {
            log.err("sshd inetd mode requires root or user '{s}' (current euid={d})", .{ login_user, euid });
            return Error.NotPrivileged;
        }
    }

    // Build sshd argv with tight hardening flags
    var argv = std.ArrayList([]const u8).init(aa);
    defer argv.deinit();
    try argv.appendSlice(&.{
        "sshd",
        "-i",
        "-e", // log to stderr so we can parse failures/success
        "-o",
        "UsePAM=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PubkeyAuthentication=yes",
        "-o",
        "AuthenticationMethods=publickey",
        "-o",
        try std.fmt.allocPrint(aa, "AuthorizedKeysCommand={s}", .{auth_keys_cmd}),
        "-o",
        try std.fmt.allocPrint(aa, "AuthorizedKeysCommandUser={s}", .{authorized_keys_user}),
        "-o",
        "AuthorizedKeysFile=none", // disable per-user authorized_keys fallback
        "-o",
        try std.fmt.allocPrint(aa, "AllowUsers={s}", .{login_user}),
        // security hardening
        "-o",
        "AllowAgentForwarding=no",
        "-o",
        "AllowTcpForwarding=no",
        "-o",
        "PermitTTY=no",
        "-o",
        "X11Forwarding=no",
        "-o",
        "PermitUserEnvironment=no",
        "-o",
        "LoginGraceTime=20",
        "-o",
        "MaxAuthTries=3",
        // env + host keys
        "-o",
        try std.fmt.allocPrint(aa, "SetEnv=PLUE_REAL_CLIENT_IP={s}", .{client_ip}),
        "-o",
        try std.fmt.allocPrint(aa, "HostKey={s}", .{hostkey_rsa}),
        "-o",
        try std.fmt.allocPrint(aa, "HostKey={s}", .{hostkey_ed25519}),
        "-o",
        "StrictModes=yes",
        "-o",
        "LogLevel=ERROR",
    });

    var child = std.process.Child.init(argv.items, aa);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    const spawn_result = child.spawn();
    if (spawn_result) |_| {
        // ok
    } else |err| {
        if (err == error.FileNotFound) return Error.SshdNotFound;
        return Error.SpawnFailed;
    }

    const to_sshd = child.stdin.?.writer();
    const from_sshd = child.stdout.?.reader();
    const err_sshd = child.stderr.?.reader();

    // Forward any initial bytes we already read (e.g., partial client banner) to sshd
    if (prebuffer.len > 0) {
        to_sshd.writeAll(prebuffer) catch |e| {
            log.err("failed to write prebuffer to sshd: {}", .{e});
            _ = child.kill() catch {};
            return;
        };
    }

    // Pump data between client and sshd using blocking copy loops
    var pump_err: ?anyerror = null;
    var stderr_tail = std.ArrayList(u8).init(aa);
    defer stderr_tail.deinit();

    var t1 = try std.Thread.spawn(.{}, struct {
        fn run(cs: std.net.Stream, rdr: anytype, perr: *?anyerror) void {
            // sshd -> client
            var buf: [4096]u8 = undefined;
            while (true) {
                const n = rdr.read(&buf) catch |e| {
                    perr.* = e;
                    break;
                };
                if (n == 0) break;
                _ = cs.writeAll(buf[0..n]) catch |e| {
                    perr.* = e;
                    break;
                };
            }
            // Do not close client stream here; owner will close in Connection.deinit()
        }
    }.run, .{ client_stream, from_sshd, &pump_err });

    var t2 = try std.Thread.spawn(.{}, struct {
        fn run(wtr: anytype, cs: std.net.Stream, perr: *?anyerror) void {
            // client -> sshd
            var buf: [4096]u8 = undefined;
            while (true) {
                const n = cs.read(&buf) catch |e| {
                    perr.* = e;
                    break;
                };
                if (n == 0) break;
                _ = wtr.writeAll(buf[0..n]) catch |e| {
                    perr.* = e;
                    break;
                };
            }
            // EOF to sshd stdin is implied when writer drops; nothing to flush here
        }
    }.run, .{ to_sshd, client_stream, &pump_err });

    var t3 = try std.Thread.spawn(.{}, struct {
        fn run(rdr: anytype, tail: *std.ArrayList(u8), ip: []const u8, rl: *rate_limit.RateLimiter) void {
            var line_buf: [2048]u8 = undefined;
            var filled: usize = 0;
            var buf: [1024]u8 = undefined;
            while (true) {
                const n = rdr.read(&buf) catch break;
                if (n == 0) break;
                // keep a tail for diagnostics
                tailBufferAppend(tail, buf[0..n], 4096) catch {};
                // simple line accumulator
                var i: usize = 0;
                while (i < n) : (i += 1) {
                    const b = buf[i];
                    if (filled < line_buf.len) {
                        line_buf[filled] = b;
                        filled += 1;
                    }
                    if (b == '\n') {
                        const line = std.mem.trimRight(u8, line_buf[0..filled], "\r\n");
                        // Detect auth failures/success from sshd stderr (-e)
                        if (std.mem.indexOf(u8, line, "Failed publickey") != null or
                            std.mem.indexOf(u8, line, "Authentication refused") != null or
                            std.mem.indexOf(u8, line, "Invalid user") != null)
                        {
                            rl.recordAuthFailure(ip);
                        } else if (std.mem.indexOf(u8, line, "Accepted publickey") != null) {
                            rl.recordAuthSuccess(ip);
                        }
                        filled = 0;
                    }
                }
            }
        }
    }.run, .{ err_sshd, &stderr_tail, client_ip, rate_limiter });

    t1.join();
    t2.join();
    // After client->sshd pump completes, explicitly close sshd stdin to signal EOF
    if (child.stdin) |stdin_file| stdin_file.close();
    t3.join();

    const term = child.wait() catch |e| {
        log.err("sshd wait error: {}", .{e});
        return;
    };

    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                log.warn("sshd exited with code {d}: {s}", .{ code, stderr_tail.items });
            }
        },
        else => {
            log.warn("sshd terminated abnormally", .{});
        },
    }
}
