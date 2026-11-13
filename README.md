# Tichor — installable communication records app

## Publish with GitHub Pages

1. Create a **public** repository named `Tichor` on GitHub.
2. Upload **the files inside this folder**, not the ZIP or a nested folder. `index.html` must be in the repository root.
3. Go to **Settings → Pages → Build and deployment**, choose **Deploy from a branch**, branch **main**, folder **/(root)**, then Save.
4. Your app will be at `https://YOUR-USERNAME.github.io/Tichor/`. Wait a few minutes for publication.
5. Android: open the URL in Chrome, menu → Install app / Add to Home screen. iPhone: open in Safari, Share → Add to Home Screen.

## Important

- The app is a PWA, not an APK or IPA. HTTPS hosting is required for installation and offline caching.
- Records are stored in local browser storage, **not GitHub**. There is no login, encryption at rest, or automatic synchronization between devices.
- Back up frequently using **Export & Backup**. Browser data deletion can permanently erase records.
- Do not commit exported records or other private information to the public GitHub repository.
- Existing users on the same site/origin retain the original browser storage key for compatibility.
- If replacing an existing deployment, old home-screen icons may take time to refresh; reinstall if necessary.
