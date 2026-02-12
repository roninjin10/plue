# Skipped E2E Tests (7 tests)

**Priority:** Low
**Area:** e2e

## Description

Seven E2E tests are currently skipped, representing known bugs or unimplemented validation.

## Skipped Tests

### `e2e/cases/bugs.spec.ts`
- **BUG-013** — Invalid date format handling in milestones
- **BUG-014** — Past due date handling
- **BUG-015** — SSH key format validation on submission
- **BUG-016** — RSA key format acceptance
- **BUG-017** — Ed25519 key format acceptance

### `e2e/cases/bugs-2025-12-20.spec.ts`
- **BUG-SEC-006** — No rate limiting on login attempts
- **BUG-SEC-007** — Grep tool pattern not validated for injection

## What's Needed

Fix the underlying bugs/implement the missing validation, then unskip the tests.

## Files

- `e2e/cases/bugs.spec.ts`
- `e2e/cases/bugs-2025-12-20.spec.ts`
