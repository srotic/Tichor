# Tichor v9 — no-passphrase internet messaging

## Changes
- Registered-user chat sends messages without a shared passphrase. The existing Supabase `chat_messages` table stores messages for later retrieval, even when the recipient is not online. Recipients must sign in to read them.
- Registered-user discovery by email, username and opt-in phone number is retained from v6. Phone numbers are NOT verified; a number is not proof of identity.
- Older `e2ee1.` encrypted messages remain encrypted and can be opened with their original shared passphrase using the optional legacy field.
- Guest rooms, WebRTC calls, push subscription controls, homepage, dashboard and Supabase notification function files are preserved. Guests still use their existing room passphrase. This release changes registered chat only.

## Security model — important
New registered-user messages are **plaintext in Supabase**, NOT end-to-end encrypted. Supabase TLS protects transmission; Row Level Security should restrict reading/writing to sender and recipient. Supabase project administrators and anyone with privileged database access can read message bodies. Do not use for sensitive communications. Removing a passphrase without building a verified automatic end-to-end key exchange cannot preserve E2EE. Existing encrypted messages are not automatically migrated.

## Setup
1. Back up your current GitHub website files.
2. Upload the PUBLIC files in this package to the root of `srotic/Tichor`. Never upload VAPID private keys, webhook secrets, or private setup ZIPs.
3. This release does not require new SQL if you already completed the previous v6/v7/v8 setup. Keep existing Supabase settings, Edge Function, and database webhooks.
4. Check that `public-config.js` has the correct Supabase URL and publishable key and that `push-config.js` matches the currently configured VAPID key pair.
5. Test using two different registered accounts in separate browsers. Open a conversation, send a message, close the recipient app, send another, reopen the recipient app and verify it loads. Test push separately.

## Limitations
- Recipient must have a registered account; merely installing Tichor is not enough. The app cannot send SMS to ordinary phone numbers.
- Phone number search is opt-in and unverified. Avoid claiming verified identity.
- Offline messages are retrieved when the app reconnects; push alerts require supported OS/browser, permission, subscription, working webhook/function, and connectivity. Not guaranteed.
- Calls still require the recipient to open Tichor to answer; TURN may be necessary.
- This is a prototype; it has not been live-tested or security audited.
