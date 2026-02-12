# Session Fork Snapshot State

**Priority:** Medium
**Area:** server/routes

## Description

When forking an agent session from a specific message, the snapshot state from the parent session is not copied.

## Current State

`server/routes/sessions.zig:1162`:
```zig
// TODO: Copy snapshot state from parent session at messageId
```

## What's Needed

When creating a forked session, copy the file/workspace snapshot from the parent session at the specified message point, so the forked session starts from the same state.

## Files

- `server/routes/sessions.zig`
