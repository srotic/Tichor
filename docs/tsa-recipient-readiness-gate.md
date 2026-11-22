# TSA recipient-device readiness — V3 staging

## Database migration
Migration `tsa_recipient_device_readiness_gate` was applied only to Supabase V3 staging.

- `public.tsa_recipient_device_readiness(target uuid)` is a narrow `SECURITY INVOKER` RPC for authenticated users.
- A private-schema, `SECURITY DEFINER` helper checks `auth.uid()`, accepted contact status, and blocked-contact exclusion before reading owner-only registry metadata. It does not return private keys or raw certificates.
- The response is limited to 50 devices with state, certificate presence, evidence presence and `delivery_authorized=false` for **every row**.
- Anonymous users cannot execute either function. The helper is in an unexposed schema.
- Client `tsa-device-readiness.mjs` requires an independently pinned contact root, verifies the authenticated sender and refuses any response that purports to authorize delivery.

## Explicit security boundary
The existing device registry supports only `pending` and `revoked` device states. Neither permits message delivery. The signer evidence table remains a preview and database does not cryptographically validate its signature. No live chat sending, message routing, decryption, encryption mode or UI has been altered by this milestone.

Automatic operational multi-device E2EE remains blocked until server-verifiable active authorization, cryptographically authenticated prekey exchange, audited ratcheting sessions, fanout/receive integration, replay and membership controls and end-to-end validation have been completed.

**Do not enable mandatory E2EE or advertise this readiness endpoint as delivery authorization.**
