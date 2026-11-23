# TichorConnect V3: single active login and new-device email alerts

Status: implementation specification; not deployed. The application MUST NOT claim single-session enforcement or automatic E2EE until end-to-end tests pass.

## Required user experience
- First verified login creates the account's first encrypted device automatically.
- Each successful login establishes a new authoritative session. The previous session loses API access and its UI signs out.
- A newly seen browser/device triggers an informational email using Resend. No approval link or fingerprint is needed for ordinary first-device enrollment.
- Login must not grant access to historical E2EE keys just because a password is known. On a replacement device, existing history stays inaccessible until secure recovery; new messages must use keys authorized for that device.
- Encryption failures must never silently fall back to plaintext.

## Security implementation
1. On authenticated login, validate the JWT with Supabase Auth, including the verified `session_id` claim. Never accept a user ID or email from the browser as authority.
2. Store the account's active session ID in a private server-owned table, updated atomically under a per-user transaction lock. Store only a salted HMAC of the browser/device identifier; do not collect raw fingerprints or IP address for notification.
3. The newest session supersedes the old one. All message, mailbox, device-registration, file, call, and sensitive profile APIs must enforce `auth.jwt()->>'session_id'` against the authoritative active session ID. Protect REST tables with restrictive RLS policies and privileged endpoints with equivalent server checks. A client-side sign-out check is UX only, NOT a security boundary.
4. In the old browser, subscribe to an account-scoped session-change signal and also re-check on focus and before operations; sign out locally on supersession. Do not delete IndexedDB cryptographic keys.
5. The Resend API key and verified `from` address must be Supabase Edge Function secrets only. After first seeing a new device identifier, enqueue an email event idempotently and send it from the backend. Do not put the key in public JavaScript. Retry delivery and monitor failures; never block login on transient email failure.
6. Limit and audit session switches and notification sends; avoid an email flood. Ensure users cannot suppress another user's alerts. Do not put account tokens, private keys, device secrets or exact geolocation in emails.
7. Test two-device races, session refresh, stale JWTs, simultaneous tabs, offline return, RLS reads/writes, RPC and Edge Function paths, message and attachment sends, and failed Resend delivery. Validate with two independent accounts.
8. Plan one-time migration for the owner's test accounts only after explicit backup and loss acknowledgment. Do not globally clear browser key stores on deployment.

## Configuration needed before production
- Resend verified sender domain and `RESEND_API_KEY` configured as server secret.
- Supabase SMTP or equivalent verified email address; Resend transactional API sends security notifications, not necessarily Auth verification mail.
- Database migration for authoritative session registry, email notification outbox and restrictive RLS enforcement.
- Signed-off end-to-end encrypted message tests and session supersession tests.

## Rollout gates
- Phase A: server session registry + strict API enforcement, tested on staging.
- Phase B: Resend email outbox, idempotent new-device detection, sender verified.
- Phase C: client automatic login enrollment + superseded-session UX.
- Phase D: migration and production release only after successful cross-device and security tests.
