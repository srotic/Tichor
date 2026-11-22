# TSA automatic multi-device encryption: cryptographic envelope milestone

## Implemented in V3 staging source

`tsa-multidevice-envelope.mjs` contains a testable experimental **per-device text ciphertext envelope**.

- For each explicitly supplied, authorized/nonrevoked device, the sender derives an independent ephemeral P-256 ECDH/HKDF AES-256-GCM encryption key and authenticates sender, recipient, message ID and destination device in AES-GCM additional authenticated data.
- The sender creates an encrypted local-archive copy and separate recipient-device copies, and signs the complete envelope with the sender's ECDSA signing key.
- Local decryption selects the exact device's ciphertext copy, verifies the sender's signature, and decrypts using that device's non-extractable private encryption key.
- Unit tests cover three-device encryption/decryption, different ciphertext copies, duplicate/unauthorized/revoked targets, altered ciphertext and sender key substitution.
- The GitHub staging workflow runs these tests. The release gate asserts the helper is **not wired to live chat**.

## Known limitations and mandatory blockers

This is a **staging cryptographic primitive**, not automatic operational E2EE.

1. The `authorized` field is provided by the caller and **not yet backed by independent server-verified transactional device authorization**. It must never be supplied from an untrusted directory row.
2. No active device enrollment-to-delivery transition is in place; pending devices are not eligible for live message distribution.
3. No recipient target discovery transaction, server-side fanout, durable ciphertext transport, offline queue, device decryption UI or encrypted cross-device synchronization is wired into production chat.
4. This primitive uses ephemeral ECDH and authenticated encryption but **is not a Double Ratchet** and does not provide post-compromise recovery or the assurances of an audited messaging protocol.
5. Replay protection, negotiated protocol versions, membership completeness proofs, device lifecycle race handling, browser compatibility, independent audit and production migration remain outstanding.
6. No message size beyond 1100 UTF-8 bytes or device count beyond 16 is supported by this experimental helper.

## Production activation decision

**DO NOT ENABLE** mandatory E2EE or advertise automatic multi-device encryption as operational until the above limitations are resolved and independently assessed. The V3 application's existing chat transport has not been changed by this milestone.
