# Trusted Shell Step Type for Workflows

**Priority:** Medium
**Area:** server/workflows

## Description

Workflow shell steps use direct exec (no `sh -c`) for security. A "trusted" shell step type is needed for cases that require shell features like pipes, redirects, and variable expansion.

## Current State

`server/workflows/executor.zig:999`:
```zig
// TODO: Add a "trusted" shell step type that allows `sh -c` for advanced use cases.
```

## What's Needed

Add a `trusted_shell` step type that:
- Runs commands via `sh -c` for full shell features
- Is restricted to explicitly trusted workflows (e.g., repo-owner authored)
- Has clear security documentation about the implications

## Files

- `server/workflows/executor.zig`
