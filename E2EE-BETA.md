# TichorConnect V3 — Experimental E2EE text beta

**Do not market this as WhatsApp, Signal Protocol, or production-ready E2EE.**

## Status
Experimental opt-in encrypted **one-to-one typed text only**, developed on `feature/v3-e2ee-text-beta`, separate from `v3-development` and `main`. The V3 staging database contains the new identity-key directory; the experimental chat entry point now imports `v3-staging-config.js` targeting the separate V3 Supabase staging project. This remains an isolated branch; other pages may still have production references and must be audited before deployment. Do not merge blindly into a live branch.

## Design
- Browser Web Crypto ECDH P-256 ephemeral public/private agreement, HKDF SHA-256 and AES-256-GCM, ECDSA P-256 signatures.
- Two recipient-specific ciphertext copies (sender history, recipient), signed envelope; public identity directory in Supabase.
- Nonextractable identity private keys stored in browser IndexedDB. Public keys are insert-only per account, no server-readable private keys.
- TOFU fingerprint pinning with fail-closed change detection, manual out-of-band verification necessary.
- Plaintext is never submitted through the standard Send text workflow when encrypted-text mode is enabled. Encryption/decryption failures are surfaced.
- Legacy plaintext and old shared-passphrase messages remain as-is, **not retroactively encrypted**.

## Limitations blocking full launch
- No Signal X3DH/PQXDH + Double Ratchet, per-message ratchet state, forward secrecy, or post-compromise security.
- No secure device linking, transfer, backup, revocation, account recovery, or identity rotation. Clearing the browser can permanently lose message access.
- No independent cryptographic security audit, cross-device browser tests, or attack-surface review.
- Group conversations, images, files, voice notes, calls signaling, polls, Actions and other insert paths are **not E2EE**.
- No authenticated server binding against malicious initial public-key substitution; trust-on-first-use requires fingerprint verification.
- Per-message ephemeral sender keys alone are *not* forward secrecy when the receiver's long-term identity private key is compromised.
- The translation workflow must not transmit decrypted text to any hosted translation service without explicit informed consent. Encrypted messages are excluded from automatic translation UI.
- Metadata (sender ID, recipient ID, time, delivery/read status and message size) remains visible to the server.

## Release gate
1. Verify that all modules, navigation paths, workers and authentication callbacks use the intended isolated V3 staging Supabase endpoint; never expose a secret/service key in the browser.
2. Confirm migration and RLS on staging.
3. Run `e2ee-v3-smoke.html` from a secure origin, then use two new accounts in separate browsers to enable keys, verify fingerprints out of band, and exchange encrypted text in both directions.
4. Inspect stored `chat_messages.body`: must begin with `tc-e2ee2.` and must contain no plaintext.
5. Test changed key pin, corrupted signature, missing device key, unavailable directory, offline state, reload, XSS and translation isolation.
6. Test attachments and auxiliary workflows: do not claim they are encrypted.
7. Obtain cryptographic review and use an audited Signal Protocol implementation before claiming WhatsApp-grade messaging.

No production deployment is authorized by this beta branch.

## Testing note
The browser self-test is now available in `e2ee-v3-smoke.html`. Its passing result is not a substitute for real two-account messaging tests or an independent audit. Direct-text UI now imports `v3-staging-config.js` rather than production configuration. Extra Action, poll, and voice-note send paths refuse plaintext sends when direct-text E2EE mode is active. Other conversations and features are still not automatically E2EE.
