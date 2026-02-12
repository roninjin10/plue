# Workflow Plan JSON Serialization

**Priority:** Medium
**Area:** server/routes

## Description

When creating workflow runs, the workflow plan/config is not serialized to JSON for storage.

## Current State

`server/routes/workflows_v2.zig:257`:
```zig
.config_json = null, // TODO: Serialize workflow plan as JSON
```

## What's Needed

Serialize the parsed workflow plan DAG to JSON so it can be stored in the `workflow_runs` table and retrieved later for display/debugging.

## Files

- `server/routes/workflows_v2.zig`
