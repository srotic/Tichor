# TSA live-chat integration — independently verified original-device text

## Implemented on V3 staging
The existing chat message composer now automatically selects the experimental encrypted-direct-text path for a contact whose **complete account-root fingerprint** the user has independently verified and pinned on this browser. An explicit "Verify contact security fingerprint" action displays the comparison instructions and requires manually entered confirmation.

- `tcVerifiedRootPinned` enforces account-scoped contact identity continuity.
- `tcE2EESelected` always selects encrypted text for pinned contacts, irrespective of the old opt-in checkbox.
- The opt-in checkbox cannot downgrade a pinned conversation.
- The send path compares the observed root fingerprint to the locally pinned value immediately before encryption. Missing identity, changed keys, an unavailable local identity or encryption errors block transmission.
- The existing message insert only sends the resulting encrypted payload when encryption mode is selected. File attachments remain forbidden in encrypted text mode.
- The existing beta decryption path remains unchanged.
- Existing unencrypted messages and other tools remain explicitly labeled as **not end-to-end encrypted**.

## Scope and limitations
This change only covers **text sent from an original encryption-identity browser to the recipient's original encryption-identity browser**, with a verified recipient root. It does **not** encrypt all conversations, provision device keys for secondary browsers, deliver per-device message copies, perform offline per-device decryption or offer Signal-style Double Ratchet.

The TSA multi-device envelope remains a test-only primitive and is NOT connected to live message transport. The device registry still treats non-root devices as pending or revoked, not authorized delivery targets.

Group chats, voice notes, attachments and calls are not end-to-end encrypted. Browser compromise or clearing localStorage can remove a local trust pin. An independent security audit and a reviewed ratcheting implementation are still mandatory before production activation.

**Never describe this release as fully operational automatic multi-device E2EE.**
