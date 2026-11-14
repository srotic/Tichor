# Tichor v11 — Automatic messages, contacts, sent/delivered/read receipts

## What changes
- Messages refresh roughly every 4 seconds when the app is open, with Realtime notifications where configured.
- Saved Tichor contacts sync via Supabase for registered accounts (not device phone contacts).
- ✓ Sent = successfully inserted into database; ✓✓ Delivered = recipient signed-in app acknowledged the message while open; blue ✓✓ Read = recipient opened that conversation in a visible browser tab.
- Delivery and read are distinct events. If recipient app is closed, delivery remains pending until it is opened; background push does not count as delivered.
- Existing calling, push and guest features are retained from v9. No end-to-end encryption for new registered messages.

## One-time secure setup (no Supabase SQL Editor)
1. Back up your existing v9 GitHub repository and Supabase database.
2. In Supabase Dashboard → Project Settings → Database, copy a **Postgres connection string** (prefer the session pooler if direct IPv6 cannot connect), with the correct database password. Keep it private.
3. In GitHub repository Settings → Secrets and variables → Actions → New repository secret, name it `SUPABASE_DB_URL` and paste the complete Postgres connection string. NEVER put this string in a website file or commit it.
4. Upload all public website files from this package to the repository root, and also upload the hidden `.github` directory including its `workflows` and `migrations` subdirectories. GitHub web upload may hide dot folders on some devices; use GitHub's Add file → Create new file with the exact nested path if needed.
5. Commit to `main`. GitHub Actions → Deploy Tichor database migrations should run automatically for the included migration. Confirm it shows a green check **before** testing chat.html. If the workflow is not shown, check repository Actions settings.
6. Open the live site, refresh, and sign in as two different users. Send a message, open recipient app, then open the conversation to test three states.

**Important:** The browser CANNOT run privileged database migrations. This workflow is the secure way to automate them after you configure one private GitHub secret. The initial setup is still required. Future migrations added to `.github/migrations/` will run when committed to `main`. Only trusted maintainers should be allowed to change migrations or workflow files; enable GitHub branch protection and production environment approval for stronger safety. If the database migration fails, the website may show missing-column/table errors until it succeeds.

## Limitations
No photo/image attachments are included. No phone address-book import. No guarantee of push delivery or WebRTC calling across restrictive networks. Not live-tested against your Supabase instance; database schema may need adjustment if your v9 installation differs. Do not upload private credentials, database passwords or service-role keys to the public website.
