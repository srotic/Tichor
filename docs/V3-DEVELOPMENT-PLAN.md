# TichorConnect 3.0 — Development foundation

Status: **development only**. Production is not modified by this document.

## Goals
1. Preserve all existing accounts, messages, contacts, tasks, and learning data.
2. Make messaging, calls, translation, and task synchronization reliable.
3. Integrate Discovery Lab and TichorTrade into consistent navigation.
4. Verify authentication, Supabase row-level security, privacy and PWA installation.
5. Introduce repeatable testing and a controlled release process.

## Initial repository inspection (2026-11-19)
- Main interface: `chat.html` (~460 KB), currently a large single-file application.
- Separate modules: `discovery-lab.html` and `tichortrade-stocks.html`.
- PWA assets: `sw.js` and `manifest.webmanifest`.
- `chat.html` contains extensive browser localStorage usage; account-level persistence and synchronization must be traced feature by feature.
- `v3-development` branch already existed at the start of this work.
- This is a code-structure inspection, **not** a completed security audit or live functionality test.

## Immediate work queue
- [ ] Inventory all screens, state stores, external services and database tables.
- [ ] Document production hosting and branch deployment mappings.
- [ ] Verify Supabase RLS on every user-owned table using two test accounts.
- [ ] Write smoke tests for login, messaging, contacts, calls, tasks, and translation.
- [ ] Reproduce and resolve cross-device synchronization defects.
- [ ] Design shared navigation and extract reusable CSS/JS without changing production behavior.
- [ ] Check PWA install, service-worker caching, and update lifecycle on mobile and desktop.
- [ ] Establish staging, backup, rollback, and release checklist.

## Release safeguards
- Develop on `v3-development`; do not merge into `main` without review.
- No destructive database migrations without verified backup and recovery steps.
- Never commit secrets, private credentials, service-role keys, or user data.
- Distinguish GitHub commits from deployed and independently tested features.
- Keep educational financial simulations clearly distinguished from live market data and investment advice.

## Version 3.0 release criteria
Core workflows tested across two devices; access controls reviewed; user data preserved; no known critical defects; rollback plan documented; beta release approved.
