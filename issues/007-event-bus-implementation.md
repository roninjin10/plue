# Event Bus Implementation

**Priority:** High
**Area:** server/ai

## Description

The `EventBus` in the AI agent system is a complete no-op. Events are silently dropped.

## Current State

`server/ai/types.zig:111`:
```zig
pub fn emit(self: *EventBus, event: Event) void {
    _ = self;
    _ = event;
    // TODO: Implement event dispatch
}
```

## What's Needed

Implement event dispatch so agent events (token streaming, tool calls, completion, errors) can be consumed by:
- WebSocket broadcasting (issue #002)
- Logging/telemetry
- Other subscribers

## Files

- `server/ai/types.zig`
