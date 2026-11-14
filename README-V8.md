# Tichor v8 — background notifications (setup required)

This package adds browser push subscriptions to **registered and guest users** and a Supabase Edge Function to send notifications for new encrypted messages and incoming call offers. This is an untested integration: uploading the website alone **does not enable remote notifications**. Existing chat and WebRTC calling are preserved. The recipient must open the app to answer; automatic ringing and call connection while fully closed are not supported.

## 1. Upload website files to GitHub
Upload the website files at the ZIP root to your existing Tichor GitHub Pages repository. Do **not** upload any private keys or webhook secrets. The `supabase/functions` folder contains server-side code; it may be stored publicly, but deploying it requires Supabase Edge Functions. This is the rotated-key release. Replace `push-config.js` and refresh the site. Previously created push subscriptions may need to be recreated by enabling notifications again.

## 2. SQL
In Supabase SQL Editor run `tichor-v8-setup.sql` once (keep previous v7 schema). Enable Anonymous Sign-Ins in Supabase Authentication > Providers for guests.

## 3. Edge Function
In Supabase Dashboard > Edge Functions create a function named `tichor-push` and paste the content of `supabase/functions/tichor-push/index.ts` (or deploy using Supabase CLI). **Disable JWT verification for this webhook function**; it instead requires a secret `x-tichor-webhook-secret` header. Keep the function URL private enough to avoid nuisance requests, and always configure the secret header. Do not deploy it without the secret.

In Supabase Edge Function Secrets set:
- `VAPID_PUBLIC_KEY`: value from `push-config.js`
- `VAPID_PRIVATE_KEY`: value from the **separate private setup sheet** supplied with this package, NEVER GitHub
- `VAPID_SUBJECT`: `mailto:YOUR_REAL_EMAIL_ADDRESS` (replace with a real contact address)
- `TICHOR_WEBHOOK_SECRET`: value from the **separate private setup sheet**, NEVER GitHub

Supabase supplies `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` to Edge Functions. The service-role key must remain server-side.

## 4. Database Webhooks (4)
In Supabase Dashboard > Database > Webhooks, add an **INSERT** webhook for each of these public tables: `chat_messages`, `tichor_call_events`, `tichor_guest_messages`, `tichor_guest_calls`. Set target type to HTTP Request, POST URL `https://gblbxcrqumiraaxknwpc.supabase.co/functions/v1/tichor-push` and header `x-tichor-webhook-secret` equal to the secret from your private sheet. Use `Content-Type: application/json`. The Edge Function ignores ICE candidates, answers and hangups. Webhooks are asynchronous and may fail or be delayed; check delivery logs. Make sure the request body follows Supabase Database Webhooks default format (type, table, record).

## 5. Enable notifications on devices
Sign in at `chat.html` or enter a room at `guest.html`. Tap **Enable notifications** and allow permission. Repeat on each device. On iPhone, add the website to Home Screen first. Guest identities and subscriptions may be lost if browser data is cleared; guest invite tokens must be saved separately. The guest room's expiry is checked before push is sent, but existing room data is not automatically purged.

## 6. Test
With two devices, enable notifications on recipient, close recipient's app, send an encrypted message from sender. Test incoming call offer as well. The push notification contains **no message text or encryption passphrase**. The call recipient must tap notification and open the app to answer within the signaling window (about 60 seconds). Guest call notification opens guest.html, but the user may need to reopen the original invitation link; guest rooms are not automatically restored after browser restart.

## Troubleshooting
- `Invalid API key`: compare `public-config.js` to Supabase's publishable key (case-sensitive).
- Push setup error: check SQL table, permission, browser support, and VAPID keys.
- No push: check Edge Function logs, Database Webhooks logs, subscription row, and notification permissions.
- Browser open but chat cannot send: open conversation / guest room and enter matching shared passphrase (16+ characters).
- Calls failing across networks: existing WebRTC uses public STUN only, not a TURN relay. Push does not solve NAT/firewall issues.

This is a prototype, not a security-audited or production-reliable messaging service. Free-tier limits and browser power policies apply.
