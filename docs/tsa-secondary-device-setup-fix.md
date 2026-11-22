# TSA V3 — secondary browser onboarding fix

The encryption panel previously showed a misleading **Retry device security setup** button when the account already had an immutable encryption identity on a different browser. Retrying could not recover the original non-extractable private keys.

The V3 staging UI now identifies this case explicitly and offers **Set up this as a linked device**. This opens the existing device-verification section and registers a new pending device using its own non-extractable browser keys. The original browser must independently compare the full device fingerprint and approve its enrollment. The original account encryption identity is never overwritten or copied.

The account identity cannot be reconstructed from its public keys. **If the original device's browser storage was permanently lost, account encryption identity recovery is not implemented.** Activation of a linked device does not yet enable automatic linked-device message decryption.

The existing text-encryption beta and message delivery remain unchanged. The registration flow only prepares the current browser for trusted-device authorization; it does not activate global E2EE.
