# Tichor Modern Chat UI update

This is a visual redesign of Tichor v8, not a replacement messaging backend. It uses original Tichor green/gold branding with a familiar two-pane messenger layout, mobile message bubbles, and compact call buttons.

Upload all public website files to the GitHub repository root. Do NOT upload any private key files. No additional Supabase SQL or Edge Function changes are needed for this visual-only update. Existing push keys from the rotated v8 package are retained.

Open `chat.html` for registered chat and `guest.html` for guest rooms. The homepage remains `index.html`. After GitHub Pages deploys, hard-refresh and restart installed PWAs if necessary.

This does not add a true contact-list inbox, message delivery guarantees, or TURN infrastructure. Existing limitations still apply. This is a prototype and has not been end-to-end tested.
