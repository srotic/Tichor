# Tichor Connect v3 — Live messaging starter

## What works
- Existing local dashboard, contacts, communication records, follow-ups, exports.
- **New Live Chat** page: Supabase email/password sign-up and sign-in, finding another confirmed user by email, sending/reading messages, and optional live updates (Realtime publication required). Manual refresh also works.
- App shell PWA installation through GitHub Pages.

## Set up
1. Create a Supabase project at https://supabase.com. In SQL Editor run `supabase-setup.sql`.
2. In Authentication > URL Configuration, set Site URL to `https://srotic.github.io/Tichor/` and add `https://srotic.github.io/Tichor/**` as redirect URL. Enable email/password auth. Confirm email as prompted.
3. In Database > Publications, enable `chat_messages` for `supabase_realtime` if you want push updates. Manual refresh works without it.
4. Upload all web files to repository root `srotic/Tichor` (SQL and README may also be uploaded; SQL has no secrets). In GitHub Pages choose main/root.
5. Open Tichor > Live Chat, enter Supabase Project URL and **publishable/anon** key from project API settings. Never use a service_role/secret key in browser.
6. Create two separate user accounts (different emails), confirm them, sign in on separate browsers/devices, then message each other by registered email.

## Security and limitations
- Prototype: messages are **not end-to-end encrypted**; Supabase database administrators can access them. Do not use for confidential communications.
- Email lookup can reveal whether an address is registered; restrict this for public launch (invite codes, rate limits, abuse controls).
- No phone/video calling, SMS delivery, email inbox integration, attachments, or cloud sync of local records.
- The chat page loads the Supabase JS client from an external CDN and needs network access. Offline chat is not supported.
- Never put service-role keys or user credentials in GitHub. Back up local v2 data before updating.
- Test sign-up, policies, message delivery, and mobile install before real use.
