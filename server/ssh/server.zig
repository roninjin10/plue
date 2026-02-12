/// SSH Server for Git operations
/// Provides SSH access for git clone/push/pull operations
///
/// This is a simplified implementation that leverages OpenSSH's sshd for protocol handling
/// while implementing the git command execution and authentication in Zig.
///
/// For a full native implementation, consider using:
/// - libssh2 bindings (https://github.com/mattnite/zig-libssh2)
/// - MiSSHod pure Zig implementation (https://github.com/ringtailsoftware/misshod)
/// - ZSSH pure Zig implementation (https://git.sr.ht/~mulling/zssh)
///
const std = @import("std");
const types = @import("types.zig");
const auth = @import("auth.zig");
const session = @import("session.zig");
const proxy_protocol = @import("proxy_protocol.zig");
const rate_limit = @import("rate_limit.zig");
const connection_limit = @import("connection_limit.zig");
const security_log = @import("security_log.zig");
const health = @import("health.zig");
pub const sshd_bridge = @import("sshd_bridge.zig");
const db = @import("db");

const log = std.log.scoped(.ssh_server);

/// SSH Server Configuration
pub const Config = struct {
    /// SSH server host address
    host: []const u8 = "0.0.0.0",
    /// SSH server port (22 for Cloudflare Spectrum compatibility)
    port: u16 = 22,
    /// Enable PROXY protocol parsing (for Cloudflare Spectrum)
    proxy_protocol_enabled: bool = true,
    /// Path to SSH host key (RSA)
    host_key_path: []const u8 = "data/ssh_host_key",
    /// Path to SSH host key (Ed25519)
    host_key_ed25519_path: []const u8 = "data/ssh_host_ed25519",
    /// Maximum concurrent connections total
    max_connections: u32 = 100,
    /// Maximum concurrent connections per IP
    max_per_ip_connections: u32 = 10,
    /// Maximum connection attempts per IP per minute
    rate_limit_per_minute: u32 = 20,
    /// Maximum authentication failures before IP ban
    max_auth_failures: u32 = 5,
    /// Initial ban duration in seconds (15 minutes)
    initial_ban_duration: i64 = 15 * 60,
    /// Maximum ban duration in seconds (24 hours)
    max_ban_duration: i64 = 24 * 60 * 60,
    /// Directory containing SSH helper scripts (authorized_keys_command.sh)
    /// When empty, falls back to env PLUE_SCRIPTS_DIR or 'server/scripts'
    scripts_dir: []const u8 = "server/scripts",
    /// Login user (owner of repos, e.g. 'git')
    login_user: []const u8 = "git",
    /// User for AuthorizedKeysCommand (often same as login_user)
    authorized_keys_user: []const u8 = "git",
};

/// SSH Server
pub const Server = struct {
    allocator: std.mem.Allocator,
    config: Config,
    pool: *db.Pool,
    listener: ?std.net.Server = null,
    running: bool = false,

    /// Security components
    rate_limiter: rate_limit.RateLimiter,
    connection_limiter: connection_limit.ConnectionLimiter,

    /// Server start time for uptime tracking
    start_time: i64 = 0,

    /// Cleanup thread handle
    cleanup_thread: ?std.Thread = null,
    /// Active handler threads counter to coordinate shutdown
    active_handlers: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    pub fn init(allocator: std.mem.Allocator, config: Config, pool: *db.Pool) Server {
        return .{
            .allocator = allocator,
            .config = config,
            .pool = pool,
            .rate_limiter = rate_limit.RateLimiter.init(allocator, .{
                .max_connections_per_minute = config.rate_limit_per_minute,
                .max_auth_failures = config.max_auth_failures,
                .initial_ban_duration = config.initial_ban_duration,
                .max_ban_duration = config.max_ban_duration,
            }),
            .connection_limiter = connection_limit.ConnectionLimiter.init(allocator, .{
                .max_total_connections = config.max_connections,
                .max_per_ip_connections = config.max_per_ip_connections,
            }),
        };
    }

    pub fn deinit(self: *Server) void {
        // Stop cleanup thread
        self.running = false;
        if (self.cleanup_thread) |thread| {
            thread.join();
        }

        self.rate_limiter.deinit();
        self.connection_limiter.deinit();
        if (self.listener) |*listener| {
            listener.deinit();
        }
    }

    /// Get current health status
    pub fn getHealthStatus(self: *Server) health.HealthStatus {
        return health.getHealthStatus(
            self.running,
            self.start_time,
            &self.connection_limiter,
            &self.rate_limiter,
        );
    }

    /// Get detailed metrics for monitoring
    pub fn getDetailedMetrics(self: *Server) health.DetailedMetrics {
        return health.getDetailedMetrics(
            self.start_time,
            &self.connection_limiter,
            &self.rate_limiter,
        );
    }

    /// Note on metrics in bridge mode: post-handoff auth-failure counts are
    /// updated by parsing sshd stderr ("-e") in sshd_bridge. Pre-handoff
    /// limits (connection/rate) remain fully enforced here.

    /// Generate or load SSH host key
    fn ensureHostKey(self: *Server) !void {
        // Ensure RSA host key
        if (std.fs.cwd().access(self.config.host_key_path, .{})) {
            log.info("Using existing SSH host RSA key at {s}", .{self.config.host_key_path});
        } else |_| {
            log.info("Generating SSH host RSA key at {s}", .{self.config.host_key_path});
            if (std.fs.path.dirname(self.config.host_key_path)) |dir| {
                try std.fs.cwd().makePath(dir);
            }
            var child = std.process.Child.init(&.{
                "ssh-keygen",        "-t",                      "rsa", "-b", "4096",
                "-f",                self.config.host_key_path, "-N",  "",   "-C",
                "plue-ssh-host-key",
            }, self.allocator);
            child.stdout_behavior = .Ignore;
            child.stderr_behavior = .Ignore;
            const term = try child.spawnAndWait();
            switch (term) {
                .Exited => |code| if (code != 0) return error.KeyGenerationFailed,
                else => return error.KeyGenerationFailed,
            }
            log.info("SSH host RSA key generated successfully", .{});
        }

        // Ensure Ed25519 host key
        if (std.fs.cwd().access(self.config.host_key_ed25519_path, .{})) {
            log.info("Using existing SSH host Ed25519 key at {s}", .{self.config.host_key_ed25519_path});
        } else |_| {
            log.info("Generating SSH host Ed25519 key at {s}", .{self.config.host_key_ed25519_path});
            if (std.fs.path.dirname(self.config.host_key_ed25519_path)) |dir2| {
                try std.fs.cwd().makePath(dir2);
            }
            var child2 = std.process.Child.init(&.{
                "ssh-keygen", "-t",                              "ed25519",
                "-f",         self.config.host_key_ed25519_path, "-N",
                "",           "-C",                              "plue-ssh-host-key",
            }, self.allocator);
            child2.stdout_behavior = .Ignore;
            child2.stderr_behavior = .Ignore;
            const term2 = try child2.spawnAndWait();
            switch (term2) {
                .Exited => |code| if (code != 0) return error.KeyGenerationFailed,
                else => return error.KeyGenerationFailed,
            }
            log.info("SSH host Ed25519 key generated successfully", .{});
        }
    }

    /// Start the SSH server
    pub fn listen(self: *Server) !void {
        // Ensure host key exists
        try self.ensureHostKey();

        // Preflight is performed in main() to gate enabling SSH. Avoid duplicating
        // checks here to keep a single source of truth for enable/disable semantics.

        // Parse address
        const addr = try std.net.Address.parseIp(self.config.host, self.config.port);

        // Create TCP listener
        self.listener = try addr.listen(.{
            .reuse_address = true,
            .kernel_backlog = 128,
        });

        const listener_ptr: *std.net.Server = &self.listener.?;
        self.running = true;
        self.start_time = std.time.timestamp();

        // Start cleanup thread for expired bans and stale entries
        self.cleanup_thread = try std.Thread.spawn(.{}, cleanupTask, .{self});

        log.info("SSH server listening on {s}:{d}", .{ self.config.host, self.config.port });
        if (self.config.proxy_protocol_enabled) {
            log.info("PROXY protocol enabled (for Cloudflare Spectrum)", .{});
        }
        log.info("Security hardening enabled: rate_limit={d}/min, max_failures={d}, max_conn={d}", .{
            self.config.rate_limit_per_minute,
            self.config.max_auth_failures,
            self.config.max_connections,
        });
        log.info("Mode: external sshd bridge active (sshd -i); native SSH disabled", .{});

        // Accept connections
        while (self.running) {
            const connection = listener_ptr.accept() catch |err| {
                if (!self.running) break; // listener likely closed during shutdown
                log.err("Accept failed: {}", .{err});
                // Avoid tight loop on persistent failure
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            };

            // Handle connection in a new thread
            self.active_handlers.fetchAdd(1, .acq_rel);
            const thread = try std.Thread.spawn(.{}, struct {
                fn run(srv: *Server, conn: std.net.Server.Connection) void {
                    defer srv.active_handlers.fetchSub(1, .acq_rel);
                    handleConnectionSecure(srv, conn);
                }
            }.run, .{ self, connection });
            thread.detach();
        }
    }

    /// Cleanup task - runs periodically to remove expired bans and stale entries
    fn cleanupTask(self: *Server) void {
        while (self.running) {
            // Sleep for 5 minutes
            std.Thread.sleep(5 * std.time.ns_per_min);

            if (!self.running) break;

            self.rate_limiter.cleanup();
            self.connection_limiter.cleanup();

            log.debug("Security cleanup completed", .{});
        }
    }

    /// Stop the server
    pub fn stop(self: *Server) void {
        self.running = false;
        if (self.listener) |*listener| {
            listener.deinit();
        }
        // Wait for active handlers to drain (max 5 seconds)
        var waited_ns: u64 = 0;
        while (self.active_handlers.load(.acquire) > 0 and waited_ns < 5 * std.time.ns_per_s) : (waited_ns += 10 * std.time.ns_per_ms) {
            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }
};

/// Connection state
const Connection = struct {
    stream: std.net.Stream,
    /// Socket address (may be Cloudflare proxy IP)
    address: std.net.Address,
    /// Real client IP (from PROXY protocol, or same as address if direct)
    real_client_ip: ?[]const u8 = null,
    real_client_ip_owned: bool = false,
    authenticated: bool = false,
    auth_user: ?types.AuthUser = null,
    /// Connection start time for duration tracking
    start_time: i64 = 0,

    pub fn deinit(self: *Connection, allocator: std.mem.Allocator) void {
        if (self.auth_user) |*user| {
            allocator.free(user.username);
        }
        self.stream.close();
        if (self.real_client_ip_owned) {
            if (self.real_client_ip) |ip_slice| allocator.free(ip_slice);
        }
    }

    /// Get the client IP for logging and rate limiting
    pub fn getClientIp(self: *const Connection) []const u8 {
        return self.real_client_ip orelse "unknown";
    }
};

/// Handle a single SSH connection with security checks
fn handleConnectionSecure(
    server: *Server,
    net_connection: std.net.Server.Connection,
) void {
    var conn = Connection{
        .stream = net_connection.stream,
        .address = net_connection.address,
        .start_time = std.time.timestamp(),
    };
    defer conn.deinit(server.allocator);

    // Extract IP address for security checks
    var addr_buf: [64]u8 = undefined;
    const ip = extractIpAddress(net_connection.address, &addr_buf);

    // Log connection attempt
    security_log.logConnectionAttempt(ip);

    // Check rate limit
    server.rate_limiter.checkConnection(ip) catch |err| {
        switch (err) {
            error.IPBanned => security_log.logConnectionRejectedBanned(ip, 0),
            error.RateLimitExceeded => security_log.logConnectionRejectedRateLimit(ip),
            else => security_log.logConnectionRejectedLimit(ip, "rate limit error"),
        }
        return;
    };

    // Check connection limit
    server.connection_limiter.acquire(ip) catch |err| {
        const reason = switch (err) {
            error.TooManyConnections => "total connection limit",
            error.TooManyConnectionsFromIP => "per-IP connection limit",
            else => "connection limit error",
        };
        security_log.logConnectionRejectedLimit(ip, reason);
        return;
    };

    // Ensure connection slot is released on exit
    defer {
        server.connection_limiter.release(ip);
        const duration_ms = (std.time.timestamp() - conn.start_time) * 1000;
        const username = if (conn.auth_user) |u| u.username else null;
        security_log.logSessionClosed(ip, username, duration_ms);
    }

    // Connection accepted
    security_log.logConnectionAccepted(ip);

    log.info("SSH connection from {any}", .{conn.address});

    // Continue with the actual connection handling
    handleConnectionInner(server, &conn, ip) catch |err| {
        log.err("Connection error for {s}: {}", .{ ip, err });
    };
}

/// Inner connection handling logic (after security checks pass)
fn handleConnectionInner(
    server: *Server,
    conn: *Connection,
    ip: []const u8,
) !void {
    // New path: immediately hand off to OpenSSH sshd (inetd mode),
    // optionally parsing a PROXY header and forwarding leftover bytes.
    {
        var prebuffer: []const u8 = &.{};
        if (server.config.proxy_protocol_enabled) {
            var buf: [512]u8 = undefined;
            var filled: usize = 0;
            const cap = buf.len;

            // Initial read
            const n0 = conn.stream.read(buf[0..]) catch |err| {
                log.err("Failed to read initial data: {}", .{err});
                return err;
            };
            if (n0 == 0) {
                log.info("Connection closed before sending data", .{});
                return;
            }
            filled = n0;
            var data = buf[0..filled];

            if (proxy_protocol.hasProxyHeader(data)) {
                // Continue reading until CRLF or cap
                while (proxy_protocol.parseProxyProtocolV1(data) == null and filled < cap) {
                    const n = conn.stream.read(buf[filled..]) catch |err| {
                        log.err("Failed while reading PROXY header: {}", .{err});
                        return err;
                    };
                    if (n == 0) break;
                    filled += n;
                    data = buf[0..filled];
                }

                if (proxy_protocol.parseProxyProtocolV1(data)) |info| {
                    // Store a stable copy of client IP
                    conn.real_client_ip = try server.allocator.dupe(u8, info.client_ip);
                    conn.real_client_ip_owned = true;
                    log.info("PROXY protocol: real client {s}:{d}", .{ info.client_ip, info.client_port });
                    prebuffer = data[info.header_length..];
                } else {
                    log.warn("Invalid or incomplete PROXY header; closing connection to avoid corrupting SSH handshake", .{});
                    security_log.logConnectionRejectedLimit(ip, "malformed PROXY header");
                    return; // Do not forward partial header to sshd
                }
            } else {
                prebuffer = data;
            }
        } else {
            // No PROXY protocol; do not pre-read further to avoid eating banner
            prebuffer = &.{};
        }

        const env_ip = if (conn.real_client_ip) |rip| rip else ip;
        sshd_bridge.spawnSshdBridge(
            server.allocator,
            conn.stream,
            env_ip,
            prebuffer,
            server.config.host_key_path,
            server.config.host_key_ed25519_path,
            server.config.scripts_dir,
            server.config.login_user,
            server.config.authorized_keys_user,
            &server.rate_limiter,
        ) catch |e| {
            log.err("sshd bridge failed: {}", .{e});
        };
        return; // Handled by sshd bridge
    }
    // End of handleConnectionInner
}

// Extract IP address from socket address
fn extractIpAddress(address: std.net.Address, buf: []u8) []const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    address.format(.{}, fbs.writer()) catch return "unknown";
    return std.mem.trimRight(u8, fbs.getWritten(), "\x00\n\r ");
}

/// Handle SSH protocol with security integration
fn handleProtocolSecure(
    server: *Server,
    conn: *Connection,
    ip: []const u8,
) !void {
    // This function remains for future native implementation; currently unused.
    _ = server;
    _ = conn;
    _ = ip;
    return error.NotImplemented;
}

/// Handle a single SSH connection (legacy, for backward compatibility)
fn handleConnection(
    allocator: std.mem.Allocator,
    pool: *db.Pool,
    net_connection: std.net.Server.Connection,
    config: Config,
) void {
    var conn = Connection{
        .stream = net_connection.stream,
        .address = net_connection.address,
    };
    defer conn.deinit(allocator);

    log.info("SSH connection from {any}", .{conn.address});

    // Buffer for initial data (PROXY header + SSH version)
    var initial_buf: [512]u8 = undefined;
    var data_start: usize = 0;

    // Check for PROXY protocol header if enabled
    if (config.proxy_protocol_enabled) {
        // Read enough to detect and parse PROXY header
        const bytes_read = conn.stream.read(&initial_buf) catch |err| {
            log.err("Failed to read initial data: {}", .{err});
            return;
        };

        if (bytes_read == 0) {
            log.info("Connection closed before sending data", .{});
            return;
        }

        const data = initial_buf[0..bytes_read];

        // Check if this is a PROXY protocol header
        if (proxy_protocol.hasProxyHeader(data)) {
            if (proxy_protocol.parseProxyProtocolV1(data)) |info| {
                conn.real_client_ip = info.client_ip;
                data_start = info.header_length;
                log.info("PROXY protocol: real client {s}:{d}", .{
                    info.client_ip,
                    info.client_port,
                });
            } else {
                log.warn("Invalid PROXY protocol header, treating as direct connection", .{});
            }
        }

        // Process any remaining data after PROXY header (SSH version)
        const remaining = data[data_start..];
        if (remaining.len > 0) {
            // Check if SSH version is already in the buffer
            if (std.mem.indexOf(u8, remaining, "\r\n") != null or
                std.mem.indexOf(u8, remaining, "\n") != null)
            {
                // Version is complete, validate it
                if (!std.mem.startsWith(u8, remaining, "SSH-2.0-")) {
                    log.err("Unsupported SSH version: {s}", .{remaining});
                    return;
                }
                // Continue with protocol handling
            }
        }
    }

    // Send SSH version string
    conn.stream.writeAll(types.SSH_VERSION ++ "\r\n") catch |err| {
        log.err("Failed to send SSH version: {}", .{err});
        return;
    };

    // Read client version (if not already read from PROXY buffer)
    var version_buf: [255]u8 = undefined;
    const version = if (data_start > 0 and initial_buf[data_start] != 0)
        // Version was in initial buffer after PROXY header
        std.mem.sliceTo(initial_buf[data_start..], '\n')
    else
        // Need to read version separately
        readLine(&conn, &version_buf) catch |err| {
            log.err("Failed to read client version: {}", .{err});
            return;
        };

    log.info("Client version: {s}", .{version});

    // Validate SSH-2.0
    const version_trimmed = std.mem.trimRight(u8, version, "\r");
    if (!std.mem.startsWith(u8, version_trimmed, "SSH-2.0-")) {
        log.err("Unsupported SSH version: {s}", .{version});
        return;
    }

    // Legacy native path is disabled; all connections are handled by the bridge above.
    return;
}

/// Handle SSH protocol after version exchange
// Native SSH protocol handler intentionally removed while bridge mode is the only supported path.

/// Read a line from the connection
fn readLine(conn: *Connection, buffer: []u8) ![]const u8 {
    var pos: usize = 0;
    var read_buffer: [1]u8 = undefined;
    while (pos < buffer.len) {
        const n = try conn.stream.read(&read_buffer);
        if (n == 0) return error.EndOfStream;
        const byte = read_buffer[0];
        if (byte == '\n') {
            // Remove trailing \r if present
            const end = if (pos > 0 and buffer[pos - 1] == '\r') pos - 1 else pos;
            return buffer[0..end];
        }
        buffer[pos] = byte;
        pos += 1;
    }
    return error.LineTooLong;
}

/// Alternative: Create authorized_keys_command wrapper
/// This is a more practical approach that leverages OpenSSH

test "Server init" {
    const allocator = std.testing.allocator;

    // Create a mock pool (in real tests, use a test database)
    const mock_pool = @as(*db.Pool, undefined);

    const config = Config{
        .port = 0, // Random port
    };

    var server = Server.init(allocator, config, mock_pool);
    defer server.deinit();

    try std.testing.expect(!server.running);
}
