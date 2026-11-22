# TSA revocation safeguard — V3 staging

Database migration applied on V3 staging: `tsa_revoked_device_preview_withdrawal`.

When `public.tichor_e2ee_devices.state` changes from `pending` to `revoked`, the PostgreSQL AFTER UPDATE trigger `tichor_e2ee_device_preview_withdrawal` synchronously deletes all matching `public.tichor_e2ee_recipient_directory` entries. A failure in the deletion rolls back the device-state update.

## Validation
- The trigger was verified present and enabled on the V3 staging project.
- Its function is SECURITY INVOKER (`prosecdef=false`).
- Recipient directory RLS remains enabled.
- The existing device state transition remains pending -> revoked, without reactivation.

## Security boundary
This removes public discovery *previews*; it does not erase copies of keys held on other devices, establish delivery authorization, or provide session key rotation. Pending enrollment keys remain ineligible for transport. This milestone is **not a production E2EE activation**.

## Expected integration checks
1. Enroll a fresh pending test device and publish its valid preview using the existing enrollment flow.
2. Confirm an accepted contact can discover the preview with a correctly verified root fingerprint.
3. Revoke the device as its owner and verify directory rows are withdrawn.
4. Confirm old previews do not reappear and new enrollment is required.
5. Check that pending devices never become recipients in live message fanout.

No production conversation traffic should be used for this test.
