# Tichor: secure attachments and message deletion (test branch)

This is a **proposed** update, not deployed to the live app.

## What it adds
- 📎 Upload and download PDF, Word, Excel, text, JPEG, PNG, and WebP files up to 10 MB, using a **private** Supabase Storage bucket.
- 🗑 Delete for me: hides a message from the signed-in user's view only.
- 🗑 Delete for everyone: sender-only, deletes the message record (and metadata). If an attachment exists, the app removes its storage object before deleting the message.
- Existing message receipts, calling and PWA files are not intentionally modified.

## Required setup before testing
1. In Supabase, open **SQL Editor**.
2. Review and execute `.github/migrations/002_secure_attachments_and_deletion.sql` on a **test/staging Supabase project first**. This script creates tables, policies and a private storage bucket.
3. Confirm the existing `chat_messages.id` type is UUID and existing RLS SELECT policies allow participants to view their messages. If your schema differs, adjust the migration before running.
4. Test using two accounts and a non-sensitive sample file. Verify only participants can download it; test Delete for me and Delete for everyone.
5. Merge this branch only after successful tests.

## Known limitations / safety
- Attachments are private to authenticated participants but are **not end-to-end encrypted**.
- Delete for everyone removes the message and its linked attachment from the application. Previously downloaded copies cannot be recalled.
- Upload failure after message creation can leave a text-only placeholder message; handle it by deleting the placeholder.
- Message previews in Inbox/Sent may still show text from messages hidden using Delete for me. A future patch should filter previews.
- The current user interface uses browser confirmation prompts rather than a polished menu.
- Existing files are not migrated. This feature only applies to newly uploaded attachments.
- Storage object deletion and database row deletion are not one atomic transaction; administrators may need to clean up orphaned objects after failures.
