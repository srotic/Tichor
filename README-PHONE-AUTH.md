# Tichor v11.2 — Email + verified phone sign-in

## Included
- Keeps existing email/password registration and login unchanged.
- Adds phone SMS one-time-code sign-up/sign-in through Supabase Auth (`signInWithOtp` and `verifyOtp`). A phone number not previously registered may create a **new** account after verification, depending on Supabase Auth settings.
- Adds a phone-linking section inside **My profile** for existing email accounts, using `updateUser({phone})` followed by `verifyOtp` with `type: phone_change`. This preserves the existing Supabase user ID and therefore existing conversations and contacts.
- Includes the earlier fixed contacts layout and v11 message delivery/read receipts.

## Required Supabase dashboard configuration (NO SQL editor / NO migration)
1. Go to Supabase Dashboard → Authentication → Providers → Phone (menu names may vary).
2. Enable Phone sign-in, and configure a supported SMS provider and credentials (for example Twilio or another provider supported by your Supabase project). The exact providers, pricing and availability depend on your Supabase plan and region.
3. Confirm OTP settings and phone-change verification settings in Supabase Authentication. Test with a real phone. SMS verification is not guaranteed free. **Without an SMS provider, phone sign-up and sign-in will not work; email continues working.**
4. Keep your current Supabase project, Auth users, RLS, and database migrations. Do not delete/recreate existing users or run old setup SQL.
5. Upload only the new `chat.html` to your GitHub repository root, replacing the old one. You do not need to upload the SQL files again.
6. Open the chat in a fresh browser tab and refresh; installed PWA users may need to clear old cached files or reinstall if an old service worker continues serving the previous chat.

## Existing account safety
**Existing email users must sign in with email first**, then open My profile → Link a verified phone to this account and complete SMS verification. Signing up directly with a phone before linking may create a separate Supabase Auth account with a different user ID and separate conversations. This update does not merge identities or messages.

## Security
Never put SMS-provider credentials, Supabase service-role keys or database passwords in public GitHub files. Enter provider credentials only in the Supabase dashboard. SMS is vulnerable to SIM swapping; consider additional account security for sensitive use. This version is not end-to-end encrypted. Phone verification via Supabase Auth is distinct from the optional, unverified discoverable phone in the Tichor profile.

## Test checklist
1. Email sign-in still works for an existing account.
2. Existing user links a phone and verifies with `phone_change`; signs out and signs in by SMS; account and messages are unchanged.
3. A new phone-only user signs in with an SMS code and can create a profile and chat.
4. Message receipts, saved contacts, calls and notifications still work.

**Not live-tested against your Supabase Auth configuration.** Provider settings are required before SMS can be sent.
