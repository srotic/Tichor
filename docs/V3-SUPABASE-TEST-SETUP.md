# V3 Supabase account-isolation test setup

The live test is `tests/v3-supabase-rls.live.test.cjs`. It is **opt-in** and is not run by the default CI workflow. It does not require a service-role key or database administrator credentials.

## Before running

1. Prefer a **separate Supabase staging project** with the same schema and RLS policies. If using the existing project, create two disposable, nonprivileged test accounts, A and B, and confirm the `tichor_tasks` table exists.
2. Set environment variables `SUPABASE_URL`, `SUPABASE_ANON_KEY` (publishable/anon key only), `TEST_A_EMAIL`, `TEST_A_PASSWORD`, `TEST_B_EMAIL`, `TEST_B_PASSWORD`. Never put these values in GitHub source files, pull requests, chat messages, or logs.
3. Run `node --test tests/v3-supabase-rls.live.test.cjs` using Node 22+. The script creates a uniquely identified task owned by A and deletes that test task in a `finally` block. Avoid running on production unless explicitly approved.
4. A passing result verifies **only the tested `tichor_tasks` operations and policy behavior at that time**. It does not certify all tables, storage buckets, messages, or broader application security.

## Assertions

- Both users authenticate and have different user IDs.
- A can insert and read its own test task.
- B cannot read, update, or delete A's task.
- B cannot forge an insert with A's `user_id`.
- A's original task remains intact after B's attempts.

## Current limitation

The test is a controlled integration check, not a complete two-device UI test. A browser/device scenario should additionally cover logout/login, offline pending changes, sync conflicts, and the guest-to-account migration path. The CI workflow runs dependency-free source regression checks only; live tests intentionally require separately provided credentials.
