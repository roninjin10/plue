# Token Event Persistence Batching

**Priority:** Medium
**Area:** server/routes

## Description

Token events from the runner are persisted to the database one at a time instead of being batched for performance.

## Current State

`server/routes/internal.zig:212`:
```zig
// Persist to database (batch, not every token)
// TODO: Implement batching
```

## What's Needed

Buffer token events and flush them to the database in batches to reduce write amplification and improve throughput during heavy agent streaming.

## Files

- `server/routes/internal.zig`
