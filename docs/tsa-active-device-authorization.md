# TSA active-device authorization — V3 staging

## What's deployed
- A staging migration adds `active` to `tichor_e2ee_devices.state`; only an authenticated *server-side, privileged* verification call may promote `pending -> active`.
- `public.tichor_e2ee_active_device_grants` records a unique root-signed activation nonce, certificate-linked account/device binding and a strictly bounded grant expiration.
- `tsa-activate-device` is a JWT-protected Supabase Edge Function restricted to the V3 staging origin. The function validates the account JWT, original immutable account ECDSA public identity, device's key pair, signed proof of possession, original-root device approval, eligibility certificate and root-signed trust evidence. It checks grant expiry and key/nonce continuity before requesting an atomic, one-way activation.
- `public.tsa_activate_device_verified` is executable by `service_role` only, holds a row lock, verifies evidence references, records a grant and changes device status to `active` in one transaction.
- Owner-initiated revocation of pending or active devices changes status to `revoked` permanently. Database triggers withdraw published previews, trust evidence, and active grant entries together with the state update.
- The original encryption identity browser displays **Activate verified device** for a pending device when the original identity has been manually confirmed. The user must manually compare the new device's fingerprint again before signing activation.
- Tests validate root-signed nonce, key, expiry, and tampering and protect the live-chat release gate.

## Manual staging acceptance test
1. On browser A (original account identity), enable encryption and confirm its fingerprint independently.
2. On a separate browser B, log in to the same account, register a pending device and obtain its full fingerprint.
3. On A, compare B's fingerprint, save approval preview and verify the resulting trust evidence.
4. On A, press **Activate verified device**, enter B's matching fingerprint and approve activation.
5. Refresh the device list on both browsers; the device should be marked `active` and the grant should exist for the same account/device/nonce.
6. Revoke B from A; assert the device becomes `revoked` and directory, trust evidence, and activation grants are withdrawn.
7. Confirm a revoked or mismatching device cannot be reactivated; check account switching, expired certificates, wrong fingerprint, duplicate grants and browsers without the original private key.
8. Independently test that the ciphertext mailbox still refuses every live delivery and offline retrieval request.

## Security limits and risk acceptance
- This implementation enables **server-authoritative active-device status**, not operational automatic multi-device E2EE.
- The activation grant lifetime is bounded to a day and further bounded by the original signed trust evidence. **Renewal before expiry is not yet implemented**; never infer ongoing delivery eligibility from `state='active'` alone. A future delivery policy must verify a fresh, signed grant and its expiry on every send and retrieval.
- The service independently verifies the entire signature chain against the existing server-published account root, but a malicious server substituting that root may remain a threat unless contact identity transparency and out-of-band identity checks are enforced.
- The database RPC relies on a service-role Edge verifier; never expose its service credentials in the frontend. The Edge function's `verify_jwt=true` setting is mandatory.
- `tsa_e2ee_device_mailbox` INSERT, SELECT, DELETE policies remain `false`. The experimental per-device envelope and ratcheting are still not integrated into live chat.
- External cryptographic review, ratcheting sessions, safe encrypted fanout, offline decryption and multi-browser integration tests remain necessary before production E2EE claims.
