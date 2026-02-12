# JJ-Based Conflict Detection

**Priority:** High
**Area:** server/routes

## Description

Conflict detection in sessions and the landing queue is stubbed. The session endpoint returns an empty conflicts array, and the landing queue marks all files as potentially conflicted instead of actually checking for conflict markers.

## Current State

### Sessions (`server/routes/sessions.zig:966`)
```zig
// TODO: Implement JJ-based conflict detection
const query_params = try req.query();
_ = query_params.get("changeId");
try res.writer().writeAll("{\"conflicts\":[],\"hasConflicts\":false,\"currentChangeId\":null}");
```

### Landing Queue (`server/routes/landing_queue.zig:448`)
```
// TODO: In a full implementation, we'd check each file for conflict markers
// For now, we'll add all files as potentially conflicted
```

## What's Needed

1. Use jj FFI to detect actual conflict markers in changes
2. Return per-file conflict status with details
3. Integrate with the landing queue to block merges on conflicts

## Files

- `server/routes/sessions.zig`
- `server/routes/landing_queue.zig`
