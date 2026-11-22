# TSA device-copy replay protection — V3 staging

The experimental per-device ciphertext envelope now has an optional **authenticated, one-time decryption wrapper**, `decryptDeviceCopyOnce` in `tsa-replay-receipts.mjs`.

- The wrapper verifies the signed ciphertext and decrypts before atomically claiming a durable receipt in IndexedDB.
- The receipt is scoped by signed-in account, receiving device, sender, recipient and message ID.
- Repeated authenticated deliveries fail closed; invalid signatures do not consume the receipt.
- Missing or failed durable storage prevents delivery of plaintext.
- The staging CI runs round-trip, replay, tamper and storage-failure tests.

## Security boundary

This milestone is experimental and **does not turn on linked-device messaging**. The current database readiness RPC still returns `delivery_authorized=false`, and `tsa-replay-receipts.mjs` remains absent from live chat.

An IndexedDB receipt guards against repeated decryption in the same browser profile, not replay across cleared storage, reinstallations, compromised devices or distributed device states. Clearing it resets protection; no production-grade ratchet/recovery exists. Callers must maintain an appropriately authenticated cached display for previously consumed message IDs.

**Required before automatic multi-device E2EE**: server-verified active device grants; reviewed authenticated session establishment, signed prekeys and ratcheting; recipient fanout, offline message queue, device decryption UX; cross-device testing; and independent security review.
