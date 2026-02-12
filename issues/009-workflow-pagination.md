# Workflow Run List Pagination

**Priority:** Medium
**Area:** server/routes

## Description

The workflow runs list endpoint parses but ignores the page parameter — all results are returned without pagination.

## Current State

`server/routes/workflows_v2.zig:311`:
```zig
// TODO: implement pagination
_ = std.fmt.parseInt(i32, page_str, 10) catch 1;
```

## What's Needed

Implement offset/limit pagination for the workflow runs list endpoint, consistent with how other list endpoints (issues, repos) handle pagination.

## Files

- `server/routes/workflows_v2.zig`
