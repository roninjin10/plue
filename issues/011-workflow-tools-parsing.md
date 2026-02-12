# Workflow Trigger Tools Array Parsing

**Priority:** Medium
**Area:** server/dispatch

## Description

When parsing workflow trigger definitions, the tools array is skipped.

## Current State

`server/dispatch/trigger.zig:170`:
```zig
.tools = null, // TODO: Parse tools array
```

## What's Needed

Parse the tools array from the workflow definition so agents spawned by workflow triggers have the correct tool access configured.

## Files

- `server/dispatch/trigger.zig`
