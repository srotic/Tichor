# TichorConnect V3 — End-to-end encryption release specification

**Status: DESIGN / NOT DEPLOYED.** This file is a release gate and implementation specification, not a claim that V3 has E2EE. Current new one-to-one messages, group messages, and attachments must be treated as server-readable until each corresponding acceptance criterion is met.

## Scope and threat model
- Goal: the backend stores only ciphertext for message bodies and encrypted attachments. Only authenticated participant **devices** hold private key material.
- Threats: compromised database/API, spoofed public keys, replay, lost/stolen devices, key substitution by the server, compromised browser scripts, malicious group membership changes, backup exfiltration, and metadata exposure.
- Out of scope for an E2EE claim: traffic metadata, device compromise, screenshots, forwarding, and endpoint accessibility. Document them explicitly.
- **Do not invent cryptography.** Select an actively maintained, independently reviewed Signal-Protocol-compatible client library supported on the deployed platforms, freeze exact versions and integrity hashes, and review its license, audit history, availability, maintenance, and multi-device support. A standalone AES-GCM or ECDH implementation is not a substitute for the Signal ratchet.

## Release gate: four phases, one coordinated activation
A single *final release* is allowed **only after all four phases are complete in staging and an independent security assessment signs off**. No partially encrypted traffic may be represented as E2EE. During migration, clients must never silently fall back to plaintext.

### Phase 1: one-to-one messaging
- Persistent device identity/signing keys; private material generated, retained, and unlocked **only** on the device.
- Signed prekeys, one-time prekeys, signed key bundles, bounded prekey consumption and rotation; authenticated key agreement; trust-on-first-use plus fingerprint / QR verification and key-change warnings.
- Audited Double Ratchet implementation with forward secrecy and post-compromise recovery; unique per-message keys and nonce discipline, authenticated sender/recipient/device binding, replay protection, skipped-key limits, message ordering and offline delivery.
- Transactional device registration/key revocation. Clear treatment of multiple browser profiles, cleared storage, reinstall, and lost devices.
- Encrypted payload format with explicit version/algorithm/device identifiers; prohibit sending unless session is initialized and verified in the current flow.
- Migrate existing plaintext **only after explicit user consent**; keep old messages clearly labelled as legacy and never call them E2EE.
- End-to-end cross-device tests plus server-compromise tests: no plaintext, no private keys in Supabase tables, logs, analytics, notifications, URLs, or browser error telemetry.

### Phase 2: media, attachments and calls
- Generate a new random content-encryption key for each file. Encrypt bytes locally with an authenticated algorithm; upload ciphertext only; encrypt file keys per recipient/device; authenticate metadata and enforce recipient authorization.
- Enforce type/size limits, ciphertext integrity, key rotation/revocation semantics, and safe download/open flows.
- For voice/video, verify actual peer identities and key binding. WebRTC DTLS-SRTP encrypts transport **but is not automatically equivalent to authenticated application E2EE**. Document relay/SFU threats and use a suitable insertable-stream E2EE scheme when required.
- Verify audio/video in browsers (including iOS), media transfer, reconnect, screen sharing, fallback behavior and call signaling. No claim for channels that lack end-to-end guarantees.

### Phase 3: groups and devices
- Adopt an audited, membership-aware group key-management protocol (e.g., MLS with a maintained audited implementation, or approved sender-key design). Do not reuse the one-to-one session key for a group.
- Rotate/advance epochs on member/device joins and removals. New members must not gain past history by default; removed members must not gain future keys.
- Per-device session fanout and encrypted cross-device synchronization, device-list transparency and verification, key backup and secure recovery, and cryptographic erasure limits.
- Test invite/leave/kick/role-change races, concurrent membership edits, offline devices, duplicate delivery, key rotation, backups and recovery.

### Phase 4: independent security assessment
- Commission external audit of protocol integration, frontend supply-chain integrity, key lifecycle, database policies, attachment/call paths and migration logic.
- Penetration tests: impersonation, downgrade/forced plaintext, replay, message reordering, device takeover, server-key substitution, compromised prekey store, revoked device, group membership race, and lost-device recovery.
- Resolve all critical/high findings and record medium-risk acceptance; provide reproducible test artifacts and a release sign-off from an independent reviewer.
- Only then flip E2EE-required mode across **all supported clients**; fail closed on old versions. Release monitored rollback **must not** silently re-enable plaintext delivery.

## UX + compatibility
- Show accurate current encryption status per conversation: **Not end-to-end encrypted** until protocol activation.
- Inline translation, assistant-writing aids, search, message previews and notifications must operate on-device after decrypting or use explicit user consent for content disclosure. Disable unsafe features rather than bypass encryption.
- Keep current approved-contact rules, RLS, HTTPS, rate limits and blocked-contact controls; E2EE is not an alternative to authorization.
- Document how key verification, key changes, backups, lost devices, disappearing messages and complaint/report flows work. Minors and abuse reporting need explicit privacy trade-offs.
- Avoid claims of WhatsApp-equivalent security without a rigorous protocol and deployment review.

## Current system observations (2026-11-21)
- Current V3 chat source inserts message bodies into Supabase directly, including group message bodies.
- The source contains legacy, manually shared-passphrase AES-GCM for reading older messages. It is **not** per-device automatic E2EE.
- Browser WebRTC use alone does not establish authenticated app-level media E2EE.
- Static deployment pipeline publishes HTML/JS; signing, dependency pinning and browser CSP strategy require dedicated review.

## Release decision
| Component | State |
| --- | --- |
| Phase 1 | Not implemented |
| Phase 2 | Not implemented |
| Phase 3 | Not implemented |
| Phase 4 independent audit | Not completed |
| Global E2EE required | **Disabled** |

This checklist is a **mandatory gate**, not a claim of completion.
