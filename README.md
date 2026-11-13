# Tichor Connect v5 — automatic Supabase connection and installable PWA

## Deploy on GitHub Pages
1. Replace the files in the ROOT of your `srotic/Tichor` GitHub repository with the files in this ZIP, including `public-config.js`, `chat.html`, `sw.js`, icons and `manifest.webmanifest`. Do not upload the ZIP as a single file.
2. Check `public-config.js` carefully. The Supabase URL and publishable key were transcribed from screenshots. If the key differs from the one shown in Supabase > Project Settings > API Keys, replace ONLY `SUPABASE_PUBLISHABLE_KEY` with the correct **publishable** key. NEVER add secret/service_role keys.
3. Do not rerun `supabase-setup.sql` if the previous setup already succeeded.
4. In Supabase > Authentication > URL Configuration, set Site URL to `https://srotic.github.io/Tichor/chat.html` and allow redirect URL `https://srotic.github.io/Tichor/**`.
5. Visit `https://srotic.github.io/Tichor/chat.html`. It should go directly to sign-in or messages. If you see an old screen, close/reopen the site or clear its cache and reload.

## Install on a phone
- Android Chrome: open `https://srotic.github.io/Tichor/chat.html`, then menu > Add to Home screen / Install app (availability depends on browser).
- iPhone Safari: open the same link, Share > Add to Home Screen.
- The installed app opens directly to Chat. Users do not enter Supabase project settings.
- The main Dashboard still contains locally stored, unencrypted records; the encrypted-chat feature is a separate prototype.

## Security limitations
- The Supabase project URL and **publishable** key are intentionally visible in website source; database Row Level Security must protect data.
- Shared conversation passphrases are still entered separately by both users and not saved. Use a strong unique passphrase shared via a separate trusted channel.
- This is an unaudited prototype, not production-grade E2EE. The email lookup function can allow account enumeration. Realtime publication may need enabling separately.
- Do not use for confidential or sensitive communications until security and functionality have been independently reviewed.
