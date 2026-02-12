//! Agent Streaming Handlers (SSE + WebSocket)
//!
//! Provides both SSE and WebSocket transports for real-time agent streaming.
//!
//! Protocols:
//! - SSE:    GET /api/sessions/:sessionId/stream (one-way events)
//! - WS:     GET /api/sessions/:sessionId/ws     (bi/uni-directional)
//! - Abort:  POST /api/sessions/:sessionId/abort
//!
//! Events: token, tool_start, tool_end, done, error

const std = @import("std");
const httpz = @import("httpz");
const json = @import("../lib/json.zig");
const websocket = httpz.websocket;

const log = std.log.scoped(.agent_stream);

/// SSE event types sent to client
pub const SSEEventType = enum {
    token,
    tool_start,
    tool_end,
    tool_result,
    done,
    @"error",
    keepalive,
};

/// Manager for tracking abort flags per session and managing transports
pub const ConnectionManager = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    abort_flags: std.StringHashMap(std.atomic.Value(bool)),
    /// Per-session event queues for SSE transport
    event_queues: std.StringHashMap(SessionQueue),
    /// Per-session live WebSocket connections
    ws_conns: std.StringHashMap(WsList),
    mutex: std.Thread.Mutex,

    /// Single streaming event (generic across SSE/WebSocket)
    const Event = struct {
        /// Logical event type (e.g. "token", "tool_start", ...)
        event_type: []const u8,
        /// JSON payload (not including SSE framing)
        data: []const u8,
    };

    /// Fixed-capacity per-session queue with simple trimming
    const SessionQueue = struct {
        events: std.ArrayListUnmanaged(Event) = .{},
        terminal: bool = false, // set when "done" or "error" enqueued

        pub fn init() SessionQueue {
            return .{ .events = .{}, .terminal = false };
        }

        pub fn deinit(self: *SessionQueue, allocator: std.mem.Allocator) void {
            // Free owned event strings
            for (self.events.items) |ev| {
                allocator.free(ev.event_type);
                allocator.free(ev.data);
            }
            self.events.deinit(allocator);
        }
    };

    /// Per-connection node stored on the heap to ensure a stable address.
    /// Lifetime is guarded by `use_count` so writers can safely release the
    /// manager lock while holding a temporary reference.
    const ConnRef = struct {
        conn: *websocket.Conn,
        write_mutex: std.Thread.Mutex = .{},
        use_count: usize = 0,
        closed: bool = false,
    };

    /// Per-session list of WebSocket connections (non-owning Conn.conn)
    const WsList = struct {
        items: std.ArrayListUnmanaged(*ConnRef) = .{},

        fn init() WsList {
            return .{ .items = .{} };
        }

        fn deinit(self: *WsList, allocator: std.mem.Allocator) void {
            for (self.items.items) |ptr| allocator.destroy(ptr);
            self.items.deinit(allocator);
        }
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .abort_flags = std.StringHashMap(std.atomic.Value(bool)).init(allocator),
            .event_queues = std.StringHashMap(SessionQueue).init(allocator),
            .ws_conns = std.StringHashMap(WsList).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var key_it = self.abort_flags.keyIterator();
        while (key_it.next()) |key| self.allocator.free(key.*);
        self.abort_flags.deinit();

        // Free session IDs and their queues
        var it = self.event_queues.iterator();
        while (it.next()) |entry| {
            const session_id_owned = entry.key_ptr.*;
            var queue = entry.value_ptr.*;
            queue.deinit(self.allocator);
            self.allocator.free(session_id_owned);
        }
        self.event_queues.deinit();

        // Free session IDs and any heap-allocated ConnRef nodes
        var ws_it = self.ws_conns.iterator();
        while (ws_it.next()) |entry| {
            const session_id_owned = entry.key_ptr.*;
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.free(session_id_owned);
        }
        self.ws_conns.deinit();
    }

    /// Set abort flag for a session
    pub fn abort(self: *Self, session_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.abort_flags.getPtr(session_id)) |flag| {
            flag.store(true, .release);
            log.info("Abort flag set for session: {s}", .{session_id});
        } else {
            const owned_id = try self.allocator.dupe(u8, session_id);
            const flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(true);
            try self.abort_flags.put(owned_id, flag);
            log.info("Abort flag created and set for session: {s}", .{session_id});
        }
    }

    /// Check if session is aborted
    pub fn isAborted(self: *Self, session_id: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.abort_flags.getPtr(session_id)) |flag| return flag.load(.acquire);
        return false;
    }

    /// Clear abort flag for a session (called when starting new execution)
    pub fn clearAbort(self: *Self, session_id: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.abort_flags.getPtr(session_id)) |flag| {
            flag.store(false, .release);
            log.info("Abort flag cleared for session: {s}", .{session_id});
        }
    }

    /// Remove session from tracking
    pub fn removeSession(self: *Self, session_id: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.abort_flags.fetchRemove(session_id)) |entry| {
            self.allocator.free(entry.key);
            log.info("Session removed from abort tracking: {s}", .{session_id});
        }
        if (self.event_queues.fetchRemove(session_id)) |entry| {
            var queue = entry.value;
            queue.deinit(self.allocator);
            self.allocator.free(entry.key);
            log.info("Session removed from streaming queues: {s}", .{session_id});
        }
        if (self.ws_conns.fetchRemove(session_id)) |entry| {
            entry.value.deinit(self.allocator);
            self.allocator.free(entry.key);
            log.info("Session removed from websocket connections: {s}", .{session_id});
        }
    }

    /// Ensure a queue exists for session; returns pointer inside map
    fn getOrCreateQueue(self: *Self, session_id: []const u8) !*SessionQueue {
        if (self.event_queues.getPtr(session_id)) |q| return q;
        const owned = try self.allocator.dupe(u8, session_id);
        try self.event_queues.put(owned, SessionQueue.init());
        return self.event_queues.getPtr(owned).?;
    }

    /// Ensure a WS list exists for session; returns pointer inside map
    fn getOrCreateWsList(self: *Self, session_id: []const u8) !*WsList {
        if (self.ws_conns.getPtr(session_id)) |l| return l;
        const owned = try self.allocator.dupe(u8, session_id);
        try self.ws_conns.put(owned, WsList.init());
        return self.ws_conns.getPtr(owned).?;
    }

    pub fn registerWs(self: *Self, session_id: []const u8, conn: *websocket.Conn) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const list = self.getOrCreateWsList(session_id) catch |err| {
            log.err("Failed to get/create WS list: {}", .{err});
            return;
        };
        const node = self.allocator.create(ConnRef) catch |err| {
            log.err("Failed to alloc ConnRef: {}", .{err});
            return;
        };
        node.* = .{ .conn = conn, .write_mutex = .{} };
        list.items.append(self.allocator, node) catch |err| {
            log.err("Failed to register websocket: {}", .{err});
            self.allocator.destroy(node);
        };
    }

    pub fn unregisterWs(self: *Self, session_id: []const u8, conn: *websocket.Conn) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.ws_conns.getPtr(session_id)) |list| {
            var i: usize = 0;
            while (i < list.items.items.len) : (i += 1) {
                const ref_ptr = list.items.items[i];
                if (ref_ptr.conn == conn) {
                    // Mark closed. If no writers are using it, remove now;
                    // otherwise defer actual free to broadcaster/post-write.
                    ref_ptr.closed = true;
                    if (ref_ptr.use_count == 0) {
                        _ = list.items.orderedRemove(i);
                        self.allocator.destroy(ref_ptr);
                    }
                    break;
                }
            }
        }
    }

    /// Write to a specific websocket connection using the same per-conn mutex
    /// used by broadcaster. Looks up the `ConnRef` and serializes the write.
    pub fn writeToConn(self: *Self, session_id: []const u8, conn: *websocket.Conn, data: []const u8) !void {
        // Lookup under lock and grab a guarded reference.
        self.mutex.lock();
        const list_ptr = self.ws_conns.getPtr(session_id);
        var ref_ptr: ?*ConnRef = null;
        if (list_ptr) |lp| {
            for (lp.items.items) |r| {
                if (r.conn == conn and !r.closed) {
                    r.use_count += 1;
                    ref_ptr = r;
                    break;
                }
            }
        }
        self.mutex.unlock();
        if (ref_ptr == null) return error.ConnectionNotFound;

        // Serialize writes per-connection outside the global lock.
        const r = ref_ptr.?;
        var write_err: ?anyerror = null;
        r.write_mutex.lock();
        r.conn.write(data) catch |err| {
            write_err = err;
        };
        r.write_mutex.unlock();

        // Release the guarded reference and prune if closed and unused.
        self.mutex.lock();
        const list2 = self.ws_conns.getPtr(session_id);
        if (list2) |lp| {
            // `r` must still be in the list; if it was concurrently closed,
            // keep it until use_count reaches zero.
            r.use_count -= 1;
            if (write_err != null) {
                r.closed = true;
            }
            if (r.closed and r.use_count == 0) {
                var i: usize = 0;
                while (i < lp.items.items.len) : (i += 1) {
                    if (lp.items.items[i] == r) {
                        _ = lp.items.orderedRemove(i);
                        self.allocator.destroy(r);
                        break;
                    }
                }
            }
        }
        self.mutex.unlock();

        if (write_err) |e| return e;
    }

    /// Internal: append event to session queue (with simple trimming)
    fn enqueueEvent(self: *Self, session_id: []const u8, event_type: []const u8, data_json: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const queue = self.getOrCreateQueue(session_id) catch |err| {
            log.err("Failed to get/create session queue: {}", .{err});
            return;
        };

        const et = self.allocator.dupe(u8, event_type) catch |err| {
            log.err("Failed to alloc event_type: {}", .{err});
            return;
        };
        const dj = self.allocator.dupe(u8, data_json) catch |err| {
            log.err("Failed to alloc event data: {}", .{err});
            self.allocator.free(et);
            return;
        };

        queue.events.append(self.allocator, .{ .event_type = et, .data = dj }) catch |err| {
            log.err("Failed to append event: {}", .{err});
            self.allocator.free(et);
            self.allocator.free(dj);
            return;
        };

        // Mark terminal when appropriate
        if (std.mem.eql(u8, event_type, "done") or std.mem.eql(u8, event_type, "error")) {
            queue.terminal = true;
        }

        // Trim if queue grows too large (keep last N)
        const MAX_EVENTS: usize = 4096;
        if (queue.events.items.len > MAX_EVENTS) {
            const drop = queue.events.items.len - (MAX_EVENTS / 2);
            var i: usize = 0;
            while (i < drop) : (i += 1) {
                const ev = queue.events.items[i];
                self.allocator.free(ev.event_type);
                self.allocator.free(ev.data);
            }
            // Move the last half down
            const keep = MAX_EVENTS / 2;
            std.mem.copyBackwards(Event, queue.events.items[0..keep], queue.events.items[drop..][0..keep]);
            queue.events.items.len = keep;
        }
    }

    /// Broadcast JSON over WebSocket to all connections in a session.
    /// Takes a snapshot under lock and writes outside the global lock.
    fn broadcastWsJson(self: *Self, session_id: []const u8, json_text: []const u8) void {
        // Snapshot current connections under the manager lock and guard them
        // with an in-use reference so they cannot be freed concurrently.
        self.mutex.lock();
        const list_ptr = self.ws_conns.getPtr(session_id);
        var snapshot = std.ArrayList(*ConnRef).init(self.allocator);
        if (list_ptr) |lp| {
            for (lp.items.items) |ref_ptr| {
                ref_ptr.use_count += 1;
                _ = snapshot.append(ref_ptr) catch {
                    // rollback the guard if append fails
                    ref_ptr.use_count -= 1;
                };
            }
        }
        self.mutex.unlock();
        defer snapshot.deinit();

        // Write to each connection outside the global lock.
        var failed = std.ArrayList(*ConnRef).init(self.allocator);
        defer failed.deinit();
        for (snapshot.items) |ref_ptr| {
            // Skip already-closed refs; they’ll be cleaned up on release.
            if (ref_ptr.closed) continue;
            ref_ptr.write_mutex.lock();
            ref_ptr.conn.write(json_text) catch |err| {
                ref_ptr.write_mutex.unlock();
                log.debug("WS write failed, scheduling removal: {}", .{err});
                _ = failed.append(ref_ptr) catch {};
                continue;
            };
            ref_ptr.write_mutex.unlock();
        }

        // Release references and prune closed/failed conns.
        self.mutex.lock();
        if (self.ws_conns.getPtr(session_id)) |lp| {
            // Mark failures as closed for pruning.
            for (failed.items) |bad| bad.closed = true;

            for (snapshot.items) |ref_ptr| {
                // Drop our in-use ref
                if (ref_ptr.use_count > 0) ref_ptr.use_count -= 1;
                if (ref_ptr.closed and ref_ptr.use_count == 0) {
                    var i: usize = 0;
                    while (i < lp.items.items.len) : (i += 1) {
                        if (lp.items.items[i] == ref_ptr) {
                            _ = lp.items.orderedRemove(i);
                            self.allocator.destroy(ref_ptr);
                            break;
                        }
                    }
                }
            }
        }
        self.mutex.unlock();
    }

    pub const FlushResult = struct { next_index: usize, terminal: bool, write_error: bool = false };

    /// Flush queued events since index to an SSE response writer.
    /// Locks only to snapshot events; releases the lock during network I/O.
    pub fn flushSSE(self: *Self, session_id: []const u8, writer: anytype, from_index: usize) FlushResult {
        // Snapshot under lock, duplicating event strings to avoid UAF while producer trims
        self.mutex.lock();
        const queue_ptr = self.event_queues.getPtr(session_id);
        if (queue_ptr == null) {
            self.mutex.unlock();
            return .{ .next_index = from_index, .terminal = false, .write_error = false };
        }
        const queue = queue_ptr.*;
        const total = queue.events.items.len;
        if (from_index >= total) {
            const term = queue.terminal;
            self.mutex.unlock();
            return .{ .next_index = total, .terminal = term, .write_error = false };
        }

        var to_write = std.ArrayList(Event).init(self.allocator);
        var i: usize = from_index;
        while (i < total) : (i += 1) {
            const ev = queue.events.items[i];
            const et = self.allocator.dupe(u8, ev.event_type) catch {
                self.mutex.unlock();
                to_write.deinit();
                return .{ .next_index = from_index, .terminal = queue.terminal, .write_error = true };
            };
            const dj = self.allocator.dupe(u8, ev.data) catch {
                self.allocator.free(et);
                self.mutex.unlock();
                to_write.deinit();
                return .{ .next_index = from_index, .terminal = queue.terminal, .write_error = true };
            };
            _ = to_write.append(.{ .event_type = et, .data = dj }) catch {
                self.allocator.free(et);
                self.allocator.free(dj);
                self.mutex.unlock();
                to_write.deinit();
                return .{ .next_index = from_index, .terminal = queue.terminal, .write_error = true };
            };
        }
        const terminal_now = queue.terminal;
        self.mutex.unlock();

        defer {
            for (to_write.items) |ev2| {
                self.allocator.free(ev2.event_type);
                self.allocator.free(ev2.data);
            }
            to_write.deinit();
        }

        // Write outside the lock
        var wrote: usize = 0;
        for (to_write.items) |evw| {
            writer.writeAll("event: ") catch break;
            writer.writeAll(evw.event_type) catch break;
            writer.writeAll("\n") catch break;
            writer.writeAll("data: ") catch break;
            writer.writeAll(evw.data) catch break;
            writer.writeAll("\n\n") catch break;
            wrote += 1;
        }

        const had_error = wrote != to_write.items.len;
        return .{ .next_index = from_index + wrote, .terminal = terminal_now, .write_error = had_error };
    }

    // -------------------------------------------------------------------------
    // Broadcast helpers (build compact JSON then queue + dispatch over WS)
    // -------------------------------------------------------------------------

    /// Broadcast a token event to all subscribers of a session
    pub fn broadcastToken(self: *Self, session_id: []const u8, message_id: []const u8, text: []const u8, token_index: usize) void {
        var list = std.ArrayList(u8){};
        defer list.deinit(self.allocator);
        const w = list.writer(self.allocator);
        w.writeAll("{") catch return;
        json.writeKey(w, "type") catch return;
        w.writeAll("\"token\"") catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "session_id") catch return;
        json.writeString(w, session_id) catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "message_id") catch return;
        json.writeString(w, message_id) catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "text") catch return;
        json.writeString(w, text) catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "token_index") catch return;
        json.writeNumber(w, token_index) catch return;
        w.writeAll("}") catch return;
        const msg = list.toOwnedSlice(self.allocator) catch return;
        defer self.allocator.free(msg);
        self.enqueueEvent(session_id, "token", msg);
        self.broadcastWsJson(session_id, msg);
    }

    /// Broadcast a tool start event to all subscribers of a session
    pub fn broadcastToolStart(self: *Self, session_id: []const u8, message_id: []const u8, tool_id: []const u8, tool_name: []const u8) void {
        var list = std.ArrayList(u8){};
        defer list.deinit(self.allocator);
        const w = list.writer(self.allocator);
        w.writeAll("{") catch return;
        json.writeKey(w, "type") catch return;
        w.writeAll("\"tool_start\"") catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "session_id") catch return;
        json.writeString(w, session_id) catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "message_id") catch return;
        json.writeString(w, message_id) catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "tool_id") catch return;
        json.writeString(w, tool_id) catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "tool_name") catch return;
        json.writeString(w, tool_name) catch return;
        w.writeAll("}") catch return;
        const msg = list.toOwnedSlice(self.allocator) catch return;
        defer self.allocator.free(msg);
        self.enqueueEvent(session_id, "tool_start", msg);
        self.broadcastWsJson(session_id, msg);
    }

    /// Broadcast a tool end event to all subscribers of a session
    pub fn broadcastToolEnd(self: *Self, session_id: []const u8, tool_id: []const u8, tool_state: []const u8, output: ?[]const u8) void {
        var list = std.ArrayList(u8){};
        defer list.deinit(self.allocator);
        const w = list.writer(self.allocator);
        w.writeAll("{") catch return;
        json.writeKey(w, "type") catch return;
        w.writeAll("\"tool_end\"") catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "session_id") catch return;
        json.writeString(w, session_id) catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "tool_id") catch return;
        json.writeString(w, tool_id) catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "tool_state") catch return;
        json.writeString(w, tool_state) catch return;
        if (output) |out| {
            w.writeAll(",") catch return;
            json.writeKey(w, "output") catch return;
            json.writeString(w, out) catch return;
        }
        w.writeAll("}") catch return;
        const msg = list.toOwnedSlice(self.allocator) catch return;
        defer self.allocator.free(msg);
        self.enqueueEvent(session_id, "tool_end", msg);
        self.broadcastWsJson(session_id, msg);
    }

    /// Broadcast a done event to all subscribers of a session
    pub fn broadcastDone(self: *Self, session_id: []const u8) void {
        var list = std.ArrayList(u8){};
        defer list.deinit(self.allocator);
        const w = list.writer(self.allocator);
        w.writeAll("{") catch return;
        json.writeKey(w, "type") catch return;
        w.writeAll("\"done\"") catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "session_id") catch return;
        json.writeString(w, session_id) catch return;
        w.writeAll("}") catch return;
        const msg = list.toOwnedSlice(self.allocator) catch return;
        defer self.allocator.free(msg);
        self.enqueueEvent(session_id, "done", msg);
        self.broadcastWsJson(session_id, msg);
    }

    /// Broadcast an error event to all subscribers of a session
    pub fn broadcastError(self: *Self, session_id: []const u8, message: []const u8) void {
        var list = std.ArrayList(u8){};
        defer list.deinit(self.allocator);
        const w = list.writer(self.allocator);
        w.writeAll("{") catch return;
        json.writeKey(w, "type") catch return;
        w.writeAll("\"error\"") catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "session_id") catch return;
        json.writeString(w, session_id) catch return;
        w.writeAll(",") catch return;
        json.writeKey(w, "message") catch return;
        json.writeString(w, message) catch return;
        w.writeAll("}") catch return;
        const msg = list.toOwnedSlice(self.allocator) catch return;
        defer self.allocator.free(msg);
        self.enqueueEvent(session_id, "error", msg);
        self.broadcastWsJson(session_id, msg);
    }
};

// =============================================================================
// WebSocket Client Handler
// =============================================================================

pub const WebsocketClient = struct {
    conn: *websocket.Conn,
    manager: *ConnectionManager,
    session_id: []const u8, // owned copy
    allocator: std.mem.Allocator,

    pub const Context = struct {
        manager: *ConnectionManager,
        session_id: []const u8,
        allocator: std.mem.Allocator,
    };

    pub fn init(conn: *websocket.Conn, ctx: *const Context) !WebsocketClient {
        // own a copy of session_id since req memory won't outlive the connection
        const sid = try ctx.allocator.dupe(u8, ctx.session_id);
        return .{ .conn = conn, .manager = ctx.manager, .session_id = sid, .allocator = ctx.allocator };
    }

    /// First safe point to write to the connection. Also registers with manager.
    pub fn afterInit(self: *WebsocketClient) !void {
        self.manager.registerWs(self.session_id, self.conn);
        // Send a small greeting/ack
        try self.manager.writeToConn(self.session_id, self.conn, "{\"type\":\"connected\"}");
    }

    /// Optional: receive client->server messages. For now support an abort signal.
    pub fn clientMessage(self: *WebsocketClient, data: []const u8) !void {
        if (std.mem.eql(u8, data, "abort")) {
            self.manager.abort(self.session_id) catch {};
            return self.manager.writeToConn(self.session_id, self.conn, "{\"type\":\"aborted\"}");
        }
        // Echo small pings
        if (std.mem.eql(u8, data, "ping")) {
            return self.manager.writeToConn(self.session_id, self.conn, "pong");
        }
    }

    /// Called on connection close; unregister and free state
    pub fn close(self: *WebsocketClient) void {
        self.manager.unregisterWs(self.session_id, self.conn);
        self.allocator.free(self.session_id);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "ConnectionManager init/deinit" {
    var manager = ConnectionManager.init(std.testing.allocator);
    defer manager.deinit();
}
