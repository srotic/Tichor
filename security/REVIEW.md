# Tichor security review — 2026-11-14

## Status: NOT security-certified / NOT penetration-tested
This document records source-code observations, not a completed production audit. Supabase project access was not available to the reviewer. No live database, cross-account, or deployment checks were executed.

## Confirmed in source
- Supabase Auth with persistent browser local-storage sessions and token auto-refresh.
- A shared passphrase derives AES-GCM keys for messages using PBKDF2 (310,000 iterations). This is *not* independently audited, modern device-to-device key management. The passphrase must be exchanged securely and retained by both parties.
- File uploads use a private Supabase Storage bucket and database RLS policies. **File contents are not end-to-end encrypted** before upload.
- Attachment previews use a one-hour signed URL for image thumbnails; anyone obtaining a valid signed URL may use it until expiry.
- A sender's storage SELECT policy permits objects under their UUID folder; recipient reads depend on attachment metadata. Validate policies with two accounts and confirm actual database state.
- Client uses Supabase JS from a CDN; review CSP and dependency pinning. The current @2 import is not an exact version pin.
- Session tokens are held in localStorage. XSS and compromised extensions can threaten sessions.
- GitHub Pages is static hosting; HTTP response security headers may require a different hosting provider or reverse proxy.

## Immediate priorities
1. Run `security/supabase-readonly-audit.sql` in Supabase SQL Editor and inspect all public tables, policies, grants, functions, and storage buckets. Keep the output private.
2. In Supabase Auth settings, verify email confirmations, allowed redirect URLs, password requirements, abuse protection/rate limits, and MFA options. Do not enable controls that would lock out existing users without a migration plan.
3. Use **two disposable test accounts** to attempt to read, update, delete, or download each other's messages, metadata, and storage objects. Validate sender-only delete, recipient-only read, and delete-for-me. Test unauthenticated access and signed URL expiry.
4. Before any claim of E2EE, design and implement per-device identity keys, authenticated key exchange, forward secrecy, device verification, backup/recovery, and client-side attachment encryption. Have the protocol independently reviewed. Do not invent a custom cryptographic protocol.
5. Conduct dependency review, CSP/XSS review, security headers review, incident response plan, backups and restore drill, and an independent penetration test.

## Safe production change policy
- Audit first. Keep all hardening migrations in review branches until current policy/grant results are inspected.
- Never run destructive SQL or disable access policies blindly.
- Do not publish SQL audit output containing user details, access tokens, or credentials.
- No claim of 'hack-proof' security is justified.
