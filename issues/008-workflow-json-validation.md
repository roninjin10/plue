# Workflow JSON Schema Validation

**Priority:** High
**Area:** server/workflows

## Description

The JSON schema validation for workflow prompts needs to be reimplemented.

## Current State

`server/workflows/prompt.zig:345`:
```zig
/// TODO: Re-implement validation logic.
pub fn validateJson(allocator: std.mem.Allocator, schema: std.json.Value, data: std.json.Value, ...)
```

## What's Needed

Implement JSON Schema validation for workflow input/output schemas so prompt templates can enforce type constraints on their parameters.

## Files

- `server/workflows/prompt.zig`
