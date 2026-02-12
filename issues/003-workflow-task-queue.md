# Persistent Workflow Task Queue

**Priority:** Critical
**Area:** server/dispatch

## Description

The workflow task queue uses an in-memory stub instead of a proper database-backed `workflow_tasks` table. Runner assignment works, but tasks aren't persisted — they're lost on server restart.

## Current State

`server/dispatch/queue.zig:72`:
```
// TODO(workflows): Implement proper task queue with workflow_tasks table
// For MVP, we just update the workflow_run status to indicate it's queued
// In production, this would:
// 1. Create workflow_tasks records for each step in the workflow plan
// 2. Assign to warm pool runners or create K8s Jobs
// 3. Return the task_id for tracking
```

Also at `db/root.zig:460`:
```zig
_ = runner_id; // TODO: filter by runner labels
```

Runner label filtering for task assignment is not implemented.

## What's Needed

1. Create `workflow_tasks` table in `db/schema.sql`
2. Implement task persistence in `queue.zig`
3. Add runner label matching for task assignment
4. Handle task recovery on server restart

## Files

- `server/dispatch/queue.zig`
- `db/schema.sql`
- `db/root.zig`
