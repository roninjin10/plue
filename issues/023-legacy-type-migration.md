# Legacy Workflow Type Migration

**Priority:** Low
**Area:** db

## Description

The database root module still has legacy workflow types that should be replaced by the types in `workflows.zig`.

## Current State

`db/root.zig:263`:
```zig
// TODO: Migrate routes to use workflows.zig types, then remove these legacy types
// =============================================================================
pub const WorkflowRunLegacy = struct { ... }
```

## What's Needed

Update all route handlers to use the new workflow types from `db/daos/workflows.zig` and delete the legacy structs.

## Files

- `db/root.zig`
- `server/routes/` (consumers of legacy types)
