# Tichor v12 — DNA identity, Inbox and Sent

## Deploy
1. Download and unzip the release.
2. Upload the **contents** of the extracted folder to the root of your existing GitHub repository (`main` branch), keeping filenames and the `.github` folder as applicable. Do not upload the ZIP itself.
3. Wait for GitHub Pages deployment to finish, then reload the Tichor app. On iPhone, if the old icon remains, remove and re-add the Home Screen shortcut.

## What changed
- DNA double-helix app icons (`icon-192.png`, `icon-512.png`, `tichor-icon.svg`).
- Functional Inbox, Sent and Contacts tabs within the signed-in Messages screen. They summarize the latest 200 incoming/outgoing messages and open conversations on tap.
- Updated dark-green/gold appearance. Existing Supabase auth, saved contacts, read receipts, calling and notifications remain.

No new database migration is required if v11 migrations already succeeded. The Inbox and Sent tabs are derived from existing `chat_messages`.

**Important:** Inbox and Sent show conversation previews, not separate email-like message stores. They depend on the existing Supabase row-level security policies. The unread count is based on fetched recent messages and can be incomplete for large accounts. This update was packaged and statically checked, but not tested against your live Supabase account. Email confirmation and phone SMS setup are separate. Messages are not end-to-end encrypted.
