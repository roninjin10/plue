# TUI Session List Loading

**Priority:** Medium
**Area:** tui

## Description

The TUI session list endpoint always returns an empty array due to a JSON parsing issue with Zig 0.15.

## Current State

`tui/client/client.zig:59`:
```zig
// TODO: Fix JSON parsing with new Zig 0.15 API
// For now, return empty list - sessions will be loaded in future phase
return try self.allocator.alloc(protocol.Session, 0);
```

## What's Needed

Update the JSON deserialization to use the Zig 0.15 `std.json` API so sessions can be listed in the TUI.

## Files

- `tui/client/client.zig`
