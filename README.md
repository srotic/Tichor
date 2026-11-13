# Tichor Connect v4 — encrypted messaging prototype

## Setup
1. Back up existing records before replacing the previous app.
2. Upload these files to the root of your `srotic/Tichor` GitHub repository. Keep `index.html`, `chat.html`, `manifest.webmanifest`, `sw.js` and both icons together.
3. In your Supabase Tichor project, open SQL Editor and run `supabase-setup.sql` after reviewing it. If already on v3, this script retains existing rows and updates the message length constraint.
4. Visit `https://srotic.github.io/Tichor/chat.html`, enter your Supabase Project URL and **publishable** API key (never a secret/service-role key), and sign in.
5. Both participants must register and verify their email. Open a conversation using the recipient's registered email.
6. Agree on a unique, long conversation passphrase via a **separate trusted channel**. Both participants type the same passphrase into their own Tichor app. Send a test message and verify decryption on the second device.

## Encryption and important limitations
- New chat messages are encrypted in the browser using Web Crypto AES-256-GCM with a random per-message IV, and PBKDF2-SHA256 (310,000 iterations) with a random per-message salt to derive keys from a shared passphrase. Only ciphertext is stored in `chat_messages.body`.
- Passphrases are not stored or uploaded by the app. They must be reentered after reload; forgetting them loses access to encrypted messages. Choose a strong random passphrase, not a short password.
- The server still sees metadata: participant account IDs, timestamps, message count, and approximate message lengths. Messages sent in v3 remain **plaintext in the database**; v4 does not retroactively encrypt them. v4 hides legacy plaintext in the encrypted chat display.
- **Not production-grade E2EE**: no cryptographic identity verification, automatic key exchange, forward secrecy, device/key recovery, or independent security audit. The hosting site and third-party script delivery are trust dependencies. Compromised devices, malicious site updates, or weak/shared passphrases can expose content. Supabase administrators can read legacy plaintext messages.
- The previous version's local records remain subject to its own local storage protections. This update encrypts only new messages sent via `chat.html`, not contacts, follow-ups, call logs, exports, or emails.
- GitHub Pages and Supabase free plans have limits; do not use this prototype for sensitive communications.

## Test
Use two different registered accounts, two devices/browsers, and the same long shared passphrase. Verify the other person can decrypt a new message, and that entering a wrong passphrase displays a lock warning. Inspect a new `chat_messages.body` row in Supabase: it should begin `e2ee1.` and contain no readable message text.
