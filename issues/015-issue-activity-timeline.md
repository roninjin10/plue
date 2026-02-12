# Issue Activity Timeline API

**Priority:** Medium
**Area:** ui/lib

## Description

Issue event recording and retrieval functions exist in the frontend but are stubs — recording is a no-op and retrieval returns an empty array.

## Current State

`ui/lib/git-issues.ts:1212`:
```typescript
/**
 * Record an issue event in the activity timeline
 * TODO: Migrate to API endpoint when available
 */
export async function recordIssueEvent(...) {
  // TODO: Call API endpoint to record event
  // For now, just log - don't fail the operation
}
```

`ui/lib/git-issues.ts:1230`:
```typescript
export async function getIssueEvents(...) {
  // TODO: Call API endpoint to fetch events
  // For now, return empty array
  return [];
}
```

## What's Needed

Wire these functions to the existing `issue_events` table via the Zig API — the backend already has event storage, just needs frontend integration.

## Files

- `ui/lib/git-issues.ts`
- `server/routes/issues.zig` (existing event support)
