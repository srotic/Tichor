# TSA sequential milestones — V3 staging only

## Milestone 1: Authenticated session establishment prototype

`tsa-authenticated-handshake.mjs` creates a fresh ephemeral ECDH key pair and a bounded two-minute handshake transcript. It authenticates the initiator and responder transcripts with per-device ECDSA signatures. Both sides can derive matching non-extractable AES-256-GCM session keys using ECDH and transcript-bound HKDF.

**Limitations:** Callers must independently authenticate each device signing key; no persistent server authorization or anti-replay ledger is attached to this handshake. This is not X3DH/PQXDH, Signal Double Ratchet, a production session protocol, or authorization to deliver messages. No endpoint is connected to live chat.

Tests: `tests/v3-tsa-authenticated-handshake.test.mjs`.

## Milestone 2: Ciphertext mailbox staging schema and adapter

Supabase staging migration `tsa_encrypted_mailbox_fail_closed_staging` created `public.tsa_e2ee_device_mailbox` with sender/recipient/device routing columns, a JSON ciphertext envelope and an expiry window. The table has RLS enabled, and **all authenticated INSERT, SELECT, DELETE policies are false**. Anonymous access is also denied. No transport is operational.

`tsa-device-mailbox.mjs` prepares distinct ciphertext-delivery rows from the experimental multi-device envelope, rejects malformed destinations and duplicate recipients, and explicitly throws errors for live publishing and retrieval. The adapter cannot turn itself on via a caller-provided flag.

Tests: `tests/v3-tsa-device-mailbox.test.mjs`. Deployment regression gates assert no live-chat integration exists.

## Remaining blockers to production automatic multi-device E2EE

1. Server-enforced **active**, root-signed device authorization and revocation (current registry only has pending/revoked).
2. A vetted ratcheting session protocol with signed prekeys, offline initial key agreement, post-compromise recovery, nonce/replay management and key rotation.
3. Complete recipient device list, per-device transactional fanout and metadata-only notifications.
4. Authorized encrypted-mailbox read/write policies, authenticated device claims and safe offline retrieval.
5. Cross-browser and cross-device integration tests plus a third-party cryptographic security assessment.

**Do not change the false RLS policies or claim automatic multi-device E2EE is operational until these checks are met.** Existing experimental original-device text remains the only live encrypted-text option.
