# CLI Implementation

**Priority:** Medium
**Area:** server/cli

## Description

The CLI (`server/cli.zig`) is entirely stubbed. All workflow commands print "this CLI is currently a stub" messages with instructions to use the API directly.

## Current State

`server/cli.zig:116-124`:
```zig
try writer.writeAll("Note: This CLI is currently a stub. To run workflows:\n");
try writer.writeAll("Note: This CLI is currently a stub. To view runs:\n");
try writer.writeAll("Note: This CLI is currently a stub. To view run details:\n");
try writer.writeAll("Note: This CLI is currently a stub. To watch a live run:\n");
try writer.writeAll("Note: This CLI is currently a stub. To cancel a run:\n");
```

## What's Needed

Implement CLI commands that call the Zig API to:
- `plue run <workflow>` — Trigger a workflow
- `plue runs` — List workflow runs
- `plue runs <id>` — Show run details
- `plue watch <id>` — Stream live run output
- `plue cancel <id>` — Cancel a running workflow

## Files

- `server/cli.zig`
