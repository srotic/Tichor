# TSA signed device trust evidence — V3 staging

## Implemented
- `tsa-device-trust.mjs` creates a bounded, one-day, account-root-signed evidence packet tied to an existing signed eligibility certificate and the device enrollment nonce.
- `e2ee-v3.js` writes this evidence into `public.tichor_e2ee_device_trust_evidence` only after validating the original local root private key, current registry identity keys and previously persisted eligibility certificate.
- Database uniqueness on `(user_id, nonce)` prevents replay as new ledger entries.
- Only the owner can read or insert evidence; insert requires current pending device state, a recorded certificate and a bounded issue/expiry time.
- A database trigger synchronously deletes device trust evidence when the device is revoked.
- Automated cryptographic tests reject tampering, root substitution, revoked registry status and expired signed evidence. The staging deployment workflow runs these tests.

## Explicitly NOT delivered yet
This ledger **cannot** grant message-delivery authorization. The backend enforces timestamp and ownership constraints but does not itself verify ECDSA signatures. The root private key never leaves the browser.

Reliable automatic multi-device E2EE additionally requires independently authenticated recipient roots, server-enforced active authorizations and revocation, signed prekeys, session agreement, maintained audited Double Ratchet, per-device ciphertext fanout, offline decryption and cross-device tests.

No live message routing has changed. Never treat `pending` devices or eligibility/trust evidence as automatic message recipients. E2EE-required mode stays disabled.
