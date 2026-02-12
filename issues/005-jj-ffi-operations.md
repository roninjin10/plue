# JJ FFI Bindings — Missing Operations

**Priority:** Critical
**Area:** server/routes, jj FFI

## Description

Several jj (Jujutsu) operations are referenced in route handlers but the underlying Rust FFI bindings don't exist yet. These return hardcoded error messages.

## Missing FFI Operations

### Undo / Restore / Revert (`server/routes/sessions.zig`)
- **Line 1063** — `"Undo operation not implemented in FFI"`
- **Line 1095** — `"Restore operation not implemented in FFI"`
- **Line 1217** — `"Revert operation not implemented in FFI"`
- **Line 1241** — `"Unrevert operation not implemented in FFI"`
- **Line 1284** — `"Undo turns not implemented"`

### Operation Log (`server/routes/operations.zig`)
- **Line 122** — `TODO: Once jj_list_operations is added to FFI, fetch directly from jj`
- **Line 326** — `TODO: Once jj_undo is implemented in FFI, call it here`
- **Line 430** — `TODO: Once jj_restore_operation is implemented in FFI, call it here`

### Merge / Rebase (`server/routes/landing_queue.zig`)
- **Line 659** — Missing FFI bindings:
  - `jj_merge_commits(workspace, source_id, dest_id)`
  - `jj_rebase_change(workspace, change_id, dest_id)`
  - `jj_update_bookmark(workspace, bookmark_name, commit_id)`

## What's Needed

Extend the Rust FFI layer (jj-lib bindings) to expose:
1. `jj_list_operations` — List operation log
2. `jj_undo` — Undo last operation
3. `jj_restore_operation` — Restore to a specific operation
4. `jj_revert` / `jj_unrevert` — Revert changes
5. `jj_merge_commits` — Merge two commits
6. `jj_rebase_change` — Rebase a change onto a destination
7. `jj_update_bookmark` — Move a bookmark to a commit

## Files

- `server/routes/sessions.zig`
- `server/routes/operations.zig`
- `server/routes/landing_queue.zig`
- Rust FFI crate (jj/)
