# Issue Comment Count Sorting

**Priority:** Medium
**Area:** ui/lib

## Description

Sorting issues by comment count uses `updated_at` as a proxy instead of actual comment counts.

## Current State

`ui/lib/git-issues.ts:406`:
```typescript
// TODO: Implement actual comment counting
issues.sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());
```

## What's Needed

Either include comment count in the issue response from the API, or implement a separate count query so issues can be properly sorted by most-commented.

## Files

- `ui/lib/git-issues.ts`
