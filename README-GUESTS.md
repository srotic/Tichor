# Tichor Guest Chat & Calls (free-only prototype)

This package extends Tichor v6. Existing registered chat and calls remain intact.

## Setup
1. Supabase Dashboard > Authentication > Providers > Anonymous Sign-Ins: **enable**. This is a temporary anonymous Supabase auth identity, not a permanent email/password account. A guest who clears browser data may lose access to their existing room.
2. In SQL Editor, review and run `tichor-guest-setup.sql` ONCE. Do not rerun v4/v6 scripts unless necessary.
3. Upload ALL extracted website files to the root of your existing GitHub Pages Tichor repository. Keep `public-config.js` configured with your own project's PUBLIC publishable key (never a service-role/secret key).
4. Open `https://srotic.github.io/Tichor/guest.html`. Enter a display name, create a private room, and privately send the invitation URL to one other person. The invitee opens it and chooses a display name, then joins. Existing registered users can also use this page.
5. Agree on a separate shared passphrase of at least 16 characters using another trusted channel; enter it on both devices to read messages. Both users must have the page open for calls.

## Security and operational limitations
- Room invitations are 256-bit random tokens. Only the SHA-256 hash is stored in the database. Treat invite links as passwords: anyone possessing a link can occupy the second room slot.
- Room capacity is two participants, enforced by a locked-row transaction. Membership controls read/send access through Row Level Security.
- Room invitations expire after 7 days for NEW joins. Existing participants are not automatically removed. Database rows, call signaling, and messages are not automatically deleted; schedule cleanup before public use.
- Supabase anonymous auth does NOT mean unauthenticated database access; RLS requires an authenticated (possibly anonymous) user identity.
- Message encryption is shared-passphrase AES-GCM (PBKDF2 key derivation), not audited, no identity verification or forward secrecy. Calls use browser WebRTC media encryption but the signaling data includes potentially sensitive IP/network metadata. No TURN relay; some networks will not connect.
- No background incoming calls or push notifications; keep both pages open. No Gmail/Outlook inbox integration.
- Open invitations can be abused for spam or excessive anonymous user creation. Add rate limits/CAPTCHA, quotas, moderation and retention before public launch. Free plans have limits.
- The code has not been deployed or end-to-end tested against a live Supabase project. Validate with two devices and test that a third account cannot read or join the room.
