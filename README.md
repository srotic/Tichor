# Tichor v6 — Free Chat & Browser Calls (prototype)

## Deploy
1. Back up the existing GitHub Pages repository.
2. In Supabase SQL Editor, review and run `tichor-v6-setup.sql` **once**. It adds profile and call signaling tables. It does not delete existing messages.
3. Upload all files to the root of your existing GitHub Pages repository, replacing old versions.
4. Open `https://srotic.github.io/Tichor/chat.html`; hard-refresh if an older version is cached.
5. Sign in on two separate devices/accounts. Each user should save a unique username in Profile.
6. Search the other account by @username, registered email, or discoverable international phone number.
7. For encrypted messages, agree on the same 16+ character passphrase outside Tichor.
8. For calls, keep both users' Tichor pages open; open a conversation, then tap Voice call or Video call. Accept on the other device. Grant mic/camera permissions.

## Important limits
- No paid service or external Google/Microsoft developer registrations required. Uses existing Supabase Free and GitHub Pages within their quotas.
- **This is a prototype, not a production-ready secure messenger.** Shared-passphrase messaging is not independently audited and lacks forward secrecy and identity verification.
- Browser-to-browser calls use WebRTC and a public STUN server. Without TURN, some mobile/carrier/NAT combinations will not connect. Calls are not guaranteed.
- Calls ring only while Tichor is open; no background push, native calling, or cellular dialing. Browser call media uses WebRTC encryption, but signaling SDP/ICE metadata is stored in Supabase and not end-to-end encrypted.
- Phone numbers are unverified and optional; only explicitly discoverable phone numbers can be searched. No SMS sending or verification.
- Gmail/Outlook mailbox integration is **not** included: real inbox access requires provider permissions.
- This implementation polls Supabase for call events every 1.8 seconds, which can consume free-tier quotas. Call events need a retention/cleanup plan.
- Email lookup may permit account enumeration; rate limiting, abuse prevention, and stronger security are required before public launch.
- The publishable key in `public-config.js` is client-safe; never put a service-role key there.
