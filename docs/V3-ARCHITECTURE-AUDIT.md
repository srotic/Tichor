# TichorConnect 3.0 — Architecture & synchronization audit (initial pass)

Date: 2026-11-19
Branch: `v3-development`
Scope: static source inspection of `chat.html`, `sw.js`, and `manifest.webmanifest`. No database credentials, live accounts, or production data were accessed.

## Confirmed architecture

| Area | Observed implementation | Next verification |
|---|---|---|
| Main application | Single `chat.html` file of approximately 460 KB, containing substantial UI and application logic | Separate modules behind compatibility tests |
| Authentication | Supabase `createClient`, persistent browser auth storage, session restore via `getSession`, and `onAuthStateChange` | Test sign-in, sign-out, session expiry, account switching |
| Tasks | Local task cache, pending operation queue, Supabase `tichor_tasks` upserts/deletes, periodic sync and visibility-triggered sync | Test two devices, conflicts, offline edits and RLS |
| User preferences | Browser `localStorage` stores theme and translation settings | Decide whether preferences should follow user accounts |
| Installability | `manifest.webmanifest` with standalone display and icons; `sw.js` caches assets and handles push notifications | Install on Android/iOS/desktop and verify update behavior |
| Educational/financial modules | Separate HTML modules | Shared navigation, accessibility, versioned integration |

## Findings that need attention

### A. Task import/account separation — high priority to test
The task loader scans legacy keys beginning with `tichor-tasks-v1:`, imports their contents into the active account's task cache on first load, and also imports guest tasks. This may unintentionally associate locally cached tasks from another prior user on the same browser with the newly signed-in account. **Do not assume this is safe.** Before any migration, test account A → sign out → account B on the same browser, using distinct tasks. The fix should be designed to preserve legitimate legacy data without cross-account transfer.

### B. Synchronization semantics — high priority
Tasks use a local pending queue and remote `tichor_tasks` table. Validate the exact reconciliation behavior for concurrent edits and deletions, failed writes, stale devices, and repeated authentication transitions. Confirm `user_id` is enforced by server-side row-level security; client-side filtering is not sufficient.

### C. Large single-file application — medium priority
Refactoring `chat.html` requires regression tests before extraction. Begin with noncritical presentation modules, then migrate data logic incrementally.

### D. PWA cache and notification safety — medium priority
Service worker pre-caches a fixed asset list and deletes old cache versions on activation. Test that every asset exists, that deployment updates are picked up, that offline navigation behaves correctly, and that notifications cannot open untrusted URLs. These are test items, not verified defects.

### E. Privacy claims — verification required
Source inspection alone cannot establish end-to-end encryption, production RLS correctness, secure API permissions, or compliance with Canadian privacy requirements. Do not advertise unverified guarantees.

## Two-account synchronization test matrix

| ID | Scenario | Expected outcome |
|---|---|---|
| TASK-01 | Account A adds a task on device 1, device 2 refreshes | Task appears once on device 2 |
| TASK-02 | Account A completes a task on device 2 | Device 1 receives completed state |
| TASK-03 | Account A deletes a task while offline | Deletion survives reconnect; no resurrection |
| TASK-04 | Account A signs out, B signs in on same browser | B never receives A's private tasks |
| TASK-05 | Guest creates tasks, then signs in | Explicit and safe migration behavior |
| TASK-06 | Both devices edit same task | Defined conflict resolution; no silent loss |
| TASK-07 | Remote write fails | Local edits remain queued; UI reports pending state |
| TASK-08 | Account B requests A's row via client | Supabase RLS rejects access |
| AUTH-01 | Session expires | App transitions safely without losing unsynced edits |
| PWA-01 | Install, update, reopen | Correct latest app and intact user data |

## Implementation sequence

1. Obtain a test environment with two nonproduction accounts and a safe Supabase schema inspection path.
2. Reproduce TASK-04 and TASK-05 before changing migration code.
3. Design an opt-in legacy-task import with account isolation, migration backup, and regression tests.
4. Verify server RLS on `tichor_tasks` and all other user-owned tables.
5. Fix and test synchronization conflicts and offline queue behavior.
6. Only then refactor the task module and shared navigation.

## Release gates

- No production data changes in this audit.
- No unreviewed database migration.
- No merge to `main` until account-isolation and synchronization tests pass.
- Commit success is not proof of deployed functionality.
