const std = @import("std");
const security_log = @import("security_log.zig");

pub const Error = error{
    SshdNotFound,
    SpawnFailed,
};

const log = std.log.scoped(.sshd_bridge);

fn getScriptsDir(allocator: std.mem.Allocator) ![]u8 {
    if (std.posix.getenv("PLUE_SCRIPTS_DIR")) |p| {
        return std.mem.dupe(allocator, u8, p);
    }
    // Default to repository scripts directory when running from source
    return std.mem.dupe(allocator, u8, "server/scripts");
}

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

/// Spawn OpenSSH "sshd" (inetd mode) and proxy stdio to client_stream.
/// Writes any prebuffer bytes to "sshd" stdin before proxying.
pub fn spawnSshdBridge(
    allocator: std.mem.Allocator,
    client_stream: std.net.Stream,
    client_ip: []const u8,
    prebuffer: []const u8,
    hostkey_rsa: []const u8,
    hostkey_ed25519: []const u8,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    // Resolve script paths
    const scripts_dir = try getScriptsDir(aa);
    const auth_keys_cmd = try makePath(aa, scripts_dir, "authorized_keys_command.sh");

    // Build "sshd" argv
    var argv = std.ArrayList([]const u8).init(aa);
    defer argv.deinit();
    try argv.appendSlice(&.{
        "sshd",
        "-i",
        "-o", "UsePAM=no",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "PubkeyAuthentication=yes",
        "-o", try std.fmt.allocPrint(aa, "AuthorizedKeysCommand={s}", .{auth_keys_cmd}),
        "-o", "AuthorizedKeysCommandUser=git",
        "-o", try std.fmt.allocPrint(aa, "SetEnv=PLUE_REAL_CLIENT_IP={s}", .{client_ip}),
        "-o", try std.fmt.allocPrint(aa, "HostKey={s}", .{hostkey_rsa}),
        "-o", try std.fmt.allocPrint(aa, "HostKey={s}", .{hostkey_ed25519}),
        "-o", "StrictModes=yes",
        "-o", "LogLevel=ERROR",
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
        };
    }

    // Pump client->sshd in background
    const PumpCtx = struct { reader: std.net.Stream.Reader, writer: std.io.AnyWriter };
    var client_reader = client_stream.reader();
    var to_sshd_any = std.io.anyWriter(to_sshd);
    var pump_thread = try std.Thread.spawn(.{}, struct {
        fn run(ctx: PumpCtx) void {
            var buf: [4096]u8 = undefined;
            while (true) {
                const n = ctx.reader.read(&buf) catch break;
                if (n == 0) break;
                _ = ctx.writer.writeAll(buf[0..n]) catch break;
            }
        }
    }.run, .{ PumpCtx{ .reader = client_reader, .writer = to_sshd_any } });

    // Capture stderr tail in background for diagnostics
    var err_tail = std.ArrayList(u8).init(aa);
    defer err_tail.deinit();
    var err_thread = try std.Thread.spawn(.{}, struct {
        fn run(r: std.io.AnyReader, tail: *std.ArrayList(u8)) void {
            var buf: [1024]u8 = undefined;
            while (true) {
                const n = r.read(&buf) catch break;
                if (n == 0) break;
                _ = tailBufferAppend(tail, buf[0..n], 4096) catch {};
            }
        }
    }.run, .{ std.io.anyReader(err_sshd), &err_tail });

    // Pump sshd->client in current thread
    var client_writer = client_stream.writer();
    var out_buf: [4096]u8 = undefined;
    while (true) {
        const n = from_sshd.read(&out_buf) catch |e| {
            log.debug("read from sshd failed: {}", .{e});
            break;
        };
        if (n == 0) break;
        client_writer.writeAll(out_buf[0..n]) catch |e| {
            log.debug("write to client failed: {}", .{e});
            break;
        };
    }

    // Close sshd stdin and wait
    child.stdin.?.close();
    pump_thread.join();
    err_thread.join();

    const term = child.wait() catch |e| {
        log.err("sshd bridge wait error: {}", .{e});
        return;
    };
    switch (term) {
        .Exited => |code| if (code != 0) log.warn("sshd exited with code {d}, stderr tail: {s}", .{ code, err_tail.items }),
        else => log.warn("sshd terminated abnormally", .{}),
    }
}

