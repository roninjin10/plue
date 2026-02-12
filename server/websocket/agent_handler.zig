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

    /// A single WebSocket connection reference (non-owning)
    const WsRef = struct {
        conn: *websocket.Conn,
    };

    /// Per-session list of WebSocket connections
    const WsList = struct {
        items: std.ArrayListUnmanaged(WsRef) = .{},

        fn init() WsList {
            return .{ .items = .{} };
        }

        fn deinit(self: *WsList, allocator: std.mem.Allocator) void {
            // we don't own the conn pointers; just free the list using the manager allocator
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
        while (key_it.next()) |key| {
            self.allocator.free(key.*);
        }

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

        // Free session IDs in ws_conns (connection objects owned elsewhere)
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
            // Create abort flag if it doesn't exist
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

        if (self.abort_flags.getPtr(session_id)) |flag| {
            return flag.load(.acquire);
        }
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

    /// Register a websocket connection for a session
    pub fn registerWs(self: *Self, session_id: []const u8, conn: *websocket.Conn) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const list = self.getOrCreateWsList(session_id) catch |err| {
            log.err("Failed to get/create WS list: {}", .{err});
            return;
        };
        list.items.append(self.allocator, .{ .conn = conn }) catch |err| {
            log.err("Failed to append WS conn: {}", .{err});
        };
    }

    /// Unregister a websocket connection for a session
    pub fn unregisterWs(self: *Self, session_id: []const u8, conn: *websocket.Conn) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.ws_conns.getPtr(session_id)) |list| {
            var i: usize = 0;
            while (i < list.items.items.len) : (i += 1) {
                if (list.items.items[i].conn == conn) {
                    _ = list.items.orderedRemove(i);
                    break;
                }
            }
        }
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
            // Shift remaining to front safely (overlapping move)
            const remaining = queue.events.items[drop..];
            std.mem.copyBackwards(Event, queue.events.items[0..remaining.len], remaining);
            // Update slice len; capacity unchanged
            queue.events.items = queue.events.items[0..remaining.len];
        }
    }

    /// Broadcast a JSON message to all websocket clients of a session
    fn broadcastWsJson(self: *Self, session_id: []const u8, json_text: []const u8) void {
        // Snapshot list under lock
        self.mutex.lock();
        const list_ptr = self.ws_conns.getPtr(session_id);
        var scratch = std.ArrayList(*websocket.Conn).init(self.allocator);
        if (list_ptr) |lp| {
            for (lp.items.items) |ref| {
                scratch.append(ref.conn) catch {};
            }
        }
        self.mutex.unlock();

        // Write outside of lock; drop closed connections
        var dead: std.ArrayList(*websocket.Conn) = .{};
        defer dead.deinit(self.allocator);

        for (scratch.items) |c| {
            c.write(json_text) catch |err| {
                log.debug("WS write failed, scheduling removal: {}", .{err});
                dead.append(c) catch {};
            };
        }

        if (dead.items.len > 0) {
            self.mutex.lock();
            if (self.ws_conns.getPtr(session_id)) |list| {
                for (dead.items) |dc| {
                    var i: usize = 0;
                    while (i < list.items.items.len) : (i += 1) {
                        if (list.items.items[i].conn == dc) {
                            _ = list.items.orderedRemove(i);
                            break;
                        }
                    }
                }
            }
            self.mutex.unlock();
        }
        scratch.deinit(self.allocator);
    }

    pub const FlushResult = struct { next_index: usize, terminal: bool, write_error: bool = false };

    /// Flush queued events since index to an SSE response writer.
    /// Locks only to snapshot events; releases the lock during network I/O.
    pub fn flushSSE(self: *Self, session_id: []const u8, writer: anytype, from_index: usize) FlushResult {
        // Snapshot under lock
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

        // Clone events to write outside the lock
        var to_write = std.ArrayList(Event){};
        defer to_write.deinit(self.allocator);
        var i: usize = from_index;
        while (i < total) : (i += 1) {
            const ev = queue.events.items[i];
            const et = self.allocator.dupe(u8, ev.event_type) catch break;
            const dj = self.allocator.dupe(u8, ev.data) catch {
                self.allocator.free(et);
                break;
            };
            to_write.append(self.allocator, .{ .event_type = et, .data = dj }) catch {
                self.allocator.free(et);
                self.allocator.free(dj);
                break;
            };
        }
        const term = queue.terminal;
        self.mutex.unlock();

        // Perform writes without holding the lock
        for (to_write.items, 0..) |ev, idx| {
            defer {
                self.allocator.free(ev.event_type);
                self.allocator.free(ev.data);
            }
            writer.print("event: {s}\n", .{ev.event_type}) catch |err| {
                log.warn("SSE write failed (event header): {}", .{err});
                const progressed = from_index + idx;
                return .{ .next_index = progressed, .terminal = term, .write_error = true };
            };
            writer.print("data: {s}\n\n", .{ev.data}) catch |err| {
                log.warn("SSE write failed (data): {}", .{err});
                const progressed = from_index + idx;
                return .{ .next_index = progressed, .terminal = term, .write_error = true };
            };
        }

        return .{ .next_index = total, .terminal = term, .write_error = false };
    }

    /// Broadcast a token event to all subscribers of a session
    pub fn broadcastToken(self: *Self, session_id: []const u8, message_id: []const u8, text: []const u8, token_index: usize) void {
        var list = std.ArrayList(u8){};
        defer list.deinit(self.allocator);
        const w = list.writer(self.allocator);
        // {"type":"token","session_id":"...","message_id":"...","text":"...","token_index":N}
        w.writeAll("{") catch return;
        json.writeKey(w, "type") catch return; w.writeAll("\"token\"") catch return; w.writeAll(",") catch return;
        json.writeKey(w, "session_id") catch return; json.writeString(w, session_id) catch return; w.writeAll(",") catch return;
        json.writeKey(w, "message_id") catch return; json.writeString(w, message_id) catch return; w.writeAll(",") catch return;
        json.writeKey(w, "text") catch return; json.writeString(w, text) catch return; w.writeAll(",") catch return;
        json.writeKey(w, "token_index") catch return; json.writeNumber(w, token_index) catch return; w.writeAll("}") catch return;
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
        json.writeKey(w, "type") catch return; w.writeAll("\"tool_start\"") catch return; w.writeAll(",") catch return;
        json.writeKey(w, "session_id") catch return; json.writeString(w, session_id) catch return; w.writeAll(",") catch return;
        json.writeKey(w, "message_id") catch return; json.writeString(w, message_id) catch return; w.writeAll(",") catch return;
        json.writeKey(w, "tool_id") catch return; json.writeString(w, tool_id) catch return; w.writeAll(",") catch return;
        json.writeKey(w, "tool_name") catch return; json.writeString(w, tool_name) catch return; w.writeAll("}") catch return;
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
        json.writeKey(w, "type") catch return; w.writeAll("\"tool_end\"") catch return; w.writeAll(",") catch return;
        json.writeKey(w, "session_id") catch return; json.writeString(w, session_id) catch return; w.writeAll(",") catch return;
        json.writeKey(w, "tool_id") catch return; json.writeString(w, tool_id) catch return; w.writeAll(",") catch return;
        json.writeKey(w, "tool_state") catch return; json.writeString(w, tool_state) catch return;
        if (output) |out| {
            w.writeAll(",") catch return;
            json.writeKey(w, "output") catch return; json.writeString(w, out) catch return;
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
        json.writeKey(w, "type") catch return; w.writeAll("\"done\"") catch return; w.writeAll(",") catch return;
        json.writeKey(w, "session_id") catch return; json.writeString(w, session_id) catch return;
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
        json.writeKey(w, "type") catch return; w.writeAll("\"error\"") catch return; w.writeAll(",") catch return;
        json.writeKey(w, "session_id") catch return; json.writeString(w, session_id) catch return; w.writeAll(",") catch return;
        json.writeKey(w, "message") catch return; json.writeString(w, message) catch return;
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

    pub const Context = struct {
        manager: *ConnectionManager,
        session_id: []const u8,
        allocator: std.mem.Allocator,
    };

    pub fn init(conn: *websocket.Conn, ctx: *const Context) !WebsocketClient {
        // own a copy of session_id since req memory won't outlive the connection
        const sid = try ctx.allocator.dupe(u8, ctx.session_id);
        return .{ .conn = conn, .manager = ctx.manager, .session_id = sid };
    }

    /// First safe point to write to the connection. Also registers with manager.
    pub fn afterInit(self: *WebsocketClient) !void {
        self.manager.registerWs(self.session_id, self.conn);
        // Send a small greeting/ack
        try self.conn.write("{\"type\":\"connected\"}");
    }

    /// Optional: receive client->server messages. For now support an abort signal.
    pub fn clientMessage(self: *WebsocketClient, data: []const u8) !void {
        if (std.mem.eql(u8, data, "abort")) {
            self.manager.abort(self.session_id) catch {};
            return self.conn.write("{\"type\":\"aborted\"}");
        }
        // Echo small pings
        if (std.mem.eql(u8, data, "ping")) {
            return self.conn.write("pong");
        }
    }

    /// Called on connection close; unregister and free state
    pub fn close(self: *WebsocketClient) void {
        self.manager.unregisterWs(self.session_id, self.conn);
        std.heap.page_allocator.free(self.session_id);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "ConnectionManager init/deinit" {
    var manager = ConnectionManager.init(std.testing.allocator);
    defer manager.deinit();
}
