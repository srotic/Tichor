# TSA trusted-root continuity milestone — V3 staging

## Change
The browser client now stores a manually verified contact root fingerprint under an account-scoped localStorage key (`tichor-v3-verified-contact-root:<signed-in-account-uuid>:<contact-uuid>`).

- `confirmRecipientRootForTSA` requires the currently signed-in user to compare the recipient's complete root fingerprint with the value independently received from that contact, then pins the identity.
- `discoverRecipientCertificatePreviews` requires the existing pin and refuses to proceed if the observed root differs, even when a caller supplies a matching fingerprint as an argument.
- Root changes fail closed. A future recovery/key-rotation flow must securely handle intentional changes.
- Tests cover unverified identities, mismatched fingerprints, immutable pins and account isolation.

## Security boundary
A browser localStorage pin is **not** server-validated device authorization, cannot survive clearing browser storage, and is not synchronized across devices. Malicious same-origin JavaScript, XSS and compromised browsers can still manipulate localStorage.

This milestone does NOT permit recipient-device delivery. Enrollment certificates remain previews and current device registry states remain pending or revoked. Live revocation checks, authenticated session establishment, audited Double Ratchet, encrypted media, and independent assessment are still required.

**Global automatic E2EE remains disabled.**
