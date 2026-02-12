# Hardcoded Repository Base Path

**Priority:** Low
**Area:** server/routes

## Description

The operations route handler uses a hardcoded `/tmp/plue/repos` path for repository operations instead of reading from config.

## Current State

`server/routes/operations.zig:23`:
```zig
// TODO: Make this configurable
const base_path = "/tmp/plue/repos";
```

## What's Needed

Read the repository base path from server config (`config.zig`) or environment variable to support different deployment environments.

## Files

- `server/routes/operations.zig`
- `server/config.zig`
