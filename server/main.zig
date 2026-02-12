const std = @import("std");
const httpz = @import("httpz");
const config = @import("config.zig");
const db = @import("db");
const metrics = @import("lib/metrics.zig");
const routes = @import("routes.zig");
const middleware = @import("middleware/mod.zig");
const repo_watcher = @import("services/repo_watcher.zig");
const session_cleanup = @import("services/session_cleanup.zig");
const edge_notifier = @import("services/edge_notifier.zig");
const agent_handler = @import("websocket/agent_handler.zig");
const workflows = @import("workflows/mod.zig");
const queue = @import("dispatch/queue.zig");
const ssh = @import("ssh/server.zig");

const log = std.log.scoped(.server);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Load configuration
    const cfg = config.load();
    log.info("Starting server on {s}:{d}", .{ cfg.host, cfg.port });
    log.info("Environment: {s}", .{if (cfg.is_production) "production" else "development"});

    // Log mTLS configuration
    if (cfg.mtls_enabled) {
        if (cfg.mtls_ca_path) |ca_path| {
            log.info("mTLS enabled, requiring client certs signed by CA at {s}", .{ca_path});
        } else {
            log.err("CRITICAL: mTLS enabled but PLUE_MTLS_CA_PATH not set", .{});
            if (cfg.is_production) {
                std.process.exit(1);
            }
        }
    } else {
        log.info("mTLS disabled (set PLUE_MTLS_ENABLED=true to enable)", .{});
    }

    // Initialize metrics
    metrics.init();
    log.info("Prometheus metrics initialized (available at /metrics)", .{});

    // Initialize database pool
    // Note: Size increased from 10 to 20 and timeout from 10s to 30s to handle
    // concurrent workflow execution alongside HTTP requests
    const uri = try std.Uri.parse(cfg.database_url);
    const pool = try db.Pool.initUri(allocator, uri, .{
        .size = 20,
        .timeout = 30_000,
    });
    defer pool.deinit();

    log.info("Database pool initialized", .{});

    // Initialize CSRF token store
    var csrf_store = middleware.CsrfStore.init(allocator);
    defer csrf_store.deinit();

    log.info("CSRF protection initialized", .{});

    // Initialize agent streaming connection manager (SSE-backed)
    var connection_manager = agent_handler.ConnectionManager.init(allocator);
    defer connection_manager.deinit();

    log.info("Agent streaming manager initialized (SSE/WS)", .{});

    // Initialize edge notifier
    var edge_notify = edge_notifier.EdgeNotifier.init(allocator, cfg.edge_url, cfg.edge_push_secret);
    const edge_notifier_ptr: ?*edge_notifier.EdgeNotifier = if (cfg.edge_url.len > 0) &edge_notify else null;
    if (cfg.edge_url.len > 0) {
        log.info("Edge notifier initialized (edge_url: {s})", .{cfg.edge_url});
    } else {
        log.info("Edge notifier disabled (set EDGE_URL to enable)", .{});
    }

    // Initialize repository watcher
    var watcher = repo_watcher.RepoWatcher.init(allocator, pool, .{}, edge_notifier_ptr);
    defer watcher.deinit();

    // Start watcher service
    if (cfg.watcher_enabled) {
        try watcher.start();
        log.info("Repository watcher started", .{});
    } else {
        log.info("Repository watcher disabled (set WATCHER_ENABLED=true to enable)", .{});
    }

    // Initialize session cleanup service
    var cleanup_service = session_cleanup.SessionCleanup.init(allocator, pool, .{});
    defer cleanup_service.deinit();

    // Start session cleanup service
    try cleanup_service.start();
    log.info("Session cleanup service started", .{});

    // Create server context
    var ctx = Context{
        .allocator = allocator,
        .pool = pool,
        .config = cfg,
        .csrf_store = &csrf_store,
        .repo_watcher = if (cfg.watcher_enabled) &watcher else null,
        .edge_notifier = edge_notifier_ptr,
        .connection_manager = &connection_manager,
    };

    // Initialize HTTP server
    var server = try httpz.Server(*Context).init(allocator, .{
        .port = cfg.port,
        .address = cfg.host,
    }, &ctx);
    defer server.deinit();

    // Recover any stuck tasks/runners on startup (best-effort)
    queue.recoverStuckTasks(ctx.pool) catch |e| {
        log.err("Task queue recovery failed: {}", .{e});
    };

    // Start lightweight periodic recovery loop (every 30s)
    if (true) {
        _ = try std.Thread.spawn(.{}, struct {
            fn run(p: *db.Pool) void {
                while (true) {
                    queue.recoverStuckTasks(p) catch |e| {
                        log.err("Periodic queue recovery error: {}", .{e});
                    };
                    std.time.sleep(30 * std.time.ns_per_s);
                }
            }
        }.run, .{ctx.pool});
        log.info("Started periodic task-queue recovery loop (30s)", .{});
    }

    // Configure middleware (applied in order: logger -> security -> cors -> body_limit -> rate_limit -> auth)
    log.info("Configuring middleware...", .{});
    try configureMiddleware(&server);

    // Configure routes
    try routes.configure(&server);

    // Optionally start SSH server (bridged via OpenSSH sshd)
    var ssh_srv_ptr: ?*ssh.Server = null;
    var ssh_thread: ?std.Thread = null;
    if (cfg.ssh_enabled) {
        const ssh_conf: ssh.Config = .{
            .host = cfg.ssh_host,
            .port = cfg.ssh_port,
            .proxy_protocol_enabled = true,
            .max_connections = cfg.ssh_max_connections,
            .max_per_ip_connections = cfg.ssh_max_per_ip_connections,
            .rate_limit_per_minute = cfg.ssh_rate_limit_per_minute,
            .max_auth_failures = cfg.ssh_max_auth_failures,
            .initial_ban_duration = cfg.ssh_initial_ban_duration,
            .max_ban_duration = cfg.ssh_max_ban_duration,
            .host_key_path = cfg.ssh_host_key_path,
            .host_key_ed25519_path = cfg.ssh_host_key_ed25519_path,
            .scripts_dir = cfg.ssh_scripts_dir,
            .login_user = cfg.ssh_login_user,
            .authorized_keys_user = cfg.ssh_authorized_keys_user,
        };

        // Preflight external sshd bridge requirements
        var ssh_ok = true;
        ssh.sshd_bridge.preflightCheck(
            allocator,
            ssh_conf.scripts_dir,
            ssh_conf.host_key_path,
            ssh_conf.host_key_ed25519_path,
            ssh_conf.login_user,
            ssh_conf.authorized_keys_user,
        ) catch |e| {
            std.log.err("SSH preflight failed: {}. SSH will be disabled.", .{e});
            ssh_ok = false;
        };

        if (ssh_ok) {
            var srv = ssh.Server.init(allocator, ssh_conf, &pool);
            ssh_srv_ptr = try allocator.create(ssh.Server);
            ssh_srv_ptr.?.* = srv;

            ssh_thread = try std.Thread.spawn(.{}, struct {
                fn run(s: *ssh.Server) void {
                    s.listen() catch |e| {
                        std.log.err("SSH server error: {}", .{e});
                    };
                }
            }.run, .{ssh_srv_ptr.?});
            ssh_thread.?.detach();

            std.log.info("SSH server enabled on {s}:{d}", .{ cfg.ssh_host, cfg.ssh_port });
        } else {
            std.log.info("SSH server disabled due to failed preflight", .{});
        }
    } else {
        std.log.info("SSH server disabled (set SSH_ENABLED=true to enable)", .{});
    }

    log.info("HTTP server listening on http://{s}:{d}", .{ cfg.host, cfg.port });

    server.listen() catch |err| {
        log.err("Server error: {}", .{err});
        // Stop services
        cleanup_service.stop();
        watcher.stop();
        if (ssh_srv_ptr) |s| {
            s.stop();
            s.deinit();
            allocator.destroy(s);
        }
        return err;
    };

    // Graceful shutdown path
    if (ssh_srv_ptr) |s| {
        s.stop();
        s.deinit();
        allocator.destroy(s);
    }
}

/// Server context passed to all request handlers
pub const Context = struct {
    pub const WebsocketHandler = agent_handler.WebsocketClient;
    allocator: std.mem.Allocator,
    pool: *db.Pool,
    config: config.Config,
    csrf_store: *middleware.CsrfStore,
    repo_watcher: ?*repo_watcher.RepoWatcher = null,
    edge_notifier: ?*edge_notifier.EdgeNotifier = null,
    connection_manager: ?*agent_handler.ConnectionManager = null,
    // User set by auth middleware
    user: ?User = null,
    session_key: ?[]const u8 = null,
    // Token scopes (comma-separated) set by auth middleware when using API tokens
    token_scopes: ?[]const u8 = null,
};

pub const User = struct {
    id: i32, // Changed from i64 to match Postgres INTEGER type (db/schema.sql:users.id)
    username: []const u8,
    email: ?[]const u8,
    display_name: ?[]const u8,
    is_admin: bool,
    is_active: bool,
    wallet_address: ?[]const u8,
};

/// Configure middleware in the correct order
/// Order: logger -> security -> cors -> body_limit -> rate_limit -> auth
fn configureMiddleware(server: *httpz.Server(*Context)) !void {
    _ = server;
    // Note: httpz dispatch API changed - middleware is now configured per-route
    log.info("Middleware configuration complete", .{});
    log.info("Middleware order: cors -> rate_limit -> auth", .{});
}

/// Request dispatch function that applies auth middleware to all requests
fn requestDispatch(ctx: *Context, req: *httpz.Request, res: *httpz.Response) bool {
    // Apply authentication middleware (loads user from session if present)
    middleware.auth.middleware(ctx, req, res) catch |err| {
        log.err("Auth middleware error: {}", .{err});
        res.status = 500;
        res.content_type = .JSON;
        res.writer().writeAll("{\"error\":\"Internal server error\"}") catch {};
        return false;
    };
    return true;
}

test {
    std.testing.refAllDecls(@This());
}
