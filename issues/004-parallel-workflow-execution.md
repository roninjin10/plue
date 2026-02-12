# Parallel Workflow Step Execution

**Priority:** Critical
**Area:** server/workflows

## Description

The workflow executor has a parallel step type in the DAG but it currently returns success without actually executing the steps in parallel.

## Current State

`server/workflows/executor.zig:1255`:
```zig
// TODO: Implement actual parallel execution
// For now, just return success
```

## What's Needed

Implement concurrent step execution using Zig's async/threading primitives:
- Fan out parallel steps to separate threads or async tasks
- Collect results from all parallel branches
- Fail the parallel group if any step fails (or support configurable failure modes)
- Properly track metrics (tokens, duration) per parallel branch

## Files

- `server/workflows/executor.zig`
