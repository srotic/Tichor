# Tichor v7 — Welcome screen update

This update replaces the GitHub Pages home page (`index.html`) with a mobile-friendly choice screen.

- Continue as Guest -> guest.html
- Sign In / Create Account -> chat.html
- Communication dashboard -> dashboard.html (original dashboard preserved)
- Installed PWA launches at index.html after manifest/service-worker refresh.

## Deploy
Extract and upload all files to the ROOT of the existing GitHub Pages repository, replacing matching files. Do not upload the ZIP as a single file. No new SQL setup is needed if the v7 guest setup was already completed. Supabase anonymous sign-ins must be enabled for guests.

## Note
An existing installed PWA may initially launch the older chat.html due to an installed manifest and cached service worker. Close and reopen the app after visiting the new home URL in the browser. If it still launches the old page, the user may need to remove and re-add the home screen shortcut. Do not clear browser storage casually, as guest identity and local records can be lost.

This update does not audit or guarantee the security of the messaging/calling prototype.
