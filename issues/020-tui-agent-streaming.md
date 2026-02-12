# TUI Agent Streaming (SSE)

**Priority:** Medium
**Area:** tui

## Description

The TUI's SSE streaming client is broken — it returns `SseNotImplemented` immediately. The TUI cannot stream agent responses.

## Current State

`tui/client/sse.zig:45`:
```zig
// TODO: Reimplement SSE streaming with the new HTTP API
// For now, just return an error - this will be fixed in a future phase
return error.SseNotImplemented;
```

## What's Needed

Reimplement the SSE client to work with the current HTTP API for streaming agent tokens, tool calls, and completion events.

## Files

- `tui/client/sse.zig`
