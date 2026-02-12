# WebSocket Broadcasting

**Priority:** Critical
**Area:** server/websocket

## Description

Five WebSocket broadcast functions in the agent handler are stubbed — they log debug messages but don't actually push data to connected clients. This means real-time agent streaming to the browser doesn't work over WebSockets.

## Affected Functions

All in `server/websocket/agent_handler.zig`:

- **Line 235** — `broadcastToken()` — Stream LLM text tokens to client
- **Line 246** — `broadcastToolStart()` — Notify client a tool is executing
- **Line 257** — `broadcastToolEnd()` — Notify client a tool finished
- **Line 265** — `broadcastDone()` — Notify client the agent is done
- **Line 274** — `broadcastError()` — Notify client of an error

## Current Behavior

```zig
// TODO: Implement WebSocket broadcasting
log.debug("broadcastToken called (not yet implemented)", .{});
```

## What's Needed

Implement actual WebSocket frame serialization and dispatch to connected clients via the existing `WebSocketManager` infrastructure.

## Files

- `server/websocket/agent_handler.zig`
