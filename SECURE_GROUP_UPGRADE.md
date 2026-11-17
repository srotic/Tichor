# Secure Group Media, Calling and E2EE — Implementation Gate

Status: DEVELOPMENT ONLY. No feature in this document is implemented by this file.

## Required capabilities
- Group image and document attachments with MIME/size validation, thumbnails and downloads.
- Voice notes with recording permission, preview, duration, playback and upload cancellation.
- Group voice and video calls with participant join/leave, mute, camera controls and network recovery.
- End-to-end encryption for group text, attachments and call media.

## Security architecture requirements
1. Choose an audited group messaging protocol (e.g., MLS or a well-maintained Signal-protocol implementation) rather than inventing custom cryptography.
2. Establish authenticated per-device identity keys, device verification, group membership epochs, key rotation on membership changes, and safe multi-device handling.
3. Encrypt messages and file bytes on the sender device *before* upload. Server stores ciphertext, minimal metadata and encrypted file keys only. Use authenticated encryption, unique nonces and integrity validation.
4. Define message history access for newly invited members, key backup/recovery, account removal, lost devices and revocation.
5. Protect calls with authenticated group membership and end-to-end media encryption. WebRTC transport encryption alone does not guarantee E2EE if an SFU terminates media; assess insertable streams/SFrame support, including iOS Safari.
6. Enforce server-side authorization/RLS for group membership and attachment storage. Signed download URLs are not substitutes for content encryption.
7. Translation must run locally *after* decryption; never transmit plaintext to a remote translation API by default.
8. Security review, automated tests and cross-browser device testing are mandatory before release. No E2EE claim until verified.

## Release gates
- Existing 1:1 chat and group text regressions pass.
- Group message sender identity and membership authorization tested.
- Photos, PDFs, arbitrary documents and voice notes work on iOS Safari, Android Chrome and desktop.
- Multi-party voice/video call tested for at least 3 participants and reconnection.
- Encryption verified with server-side inspection showing ciphertext only, key rotation and attachment tamper tests.
- Explicit user acceptance before merging into main / production deployment.

## Current repository observations
- Group message insert currently writes group_id, sender_id and body into tichor_group_messages.
- Existing application has attachment storage and individual voice recording logic, but group attachment and recording UI is absent.
- A WebRTC implementation exists, but group-call functionality is not established.
- Presence of crypto.subtle does not prove the application is end-to-end encrypted.
