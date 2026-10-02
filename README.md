# Daymark prototype

Daymark is a responsive prototype for a private work journal and appraisal summary app, with a small local API and account database.

## Run it

The API serves the web app and its endpoints from one origin. From this directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload
```

Then open `http://localhost:8000` (use this hostname for local passkeys; `127.0.0.1` is an IP address, not a valid passkey relying-party domain). The API documentation is available at `/docs`. The SQLite database is created as `daymark.sqlite3` in this directory by default; set `DAYMARK_DB_PATH` to choose another location. A localhost run is only reachable from this computer; cross-device sync needs the same backend deployed at an HTTPS address.

Gemini summaries use the free tier when available. Copy `.env.example` to `.env`, set `GEMINI_API_KEY`, and keep `SUMMARY_MODE=gemini`. The API key stays on the server, and only entries in the selected date range are sent. Summary generation first extracts a concise fact record for each entry in batches of 100, then writes the appraisal narrative from those records. If extraction omits an entry, the backend adds that entry's original recorded text to the evidence set. The final draft keeps source entry IDs for review. Google states that free-tier content may be used to improve its products; review [Gemini API pricing and data use](https://ai.google.dev/gemini-api/docs/pricing) before using real or sensitive appraisal notes. Quotas and free-tier availability can change. Set `SUMMARY_MODE=mock` for local-only drafts without an API call; these format recorded fields into paragraphs without AI paraphrasing. The older paid OpenAI integration remains available with `SUMMARY_MODE=openai`, `OPENAI_API_KEY`, and `OPENAI_MODEL`.

### Secure sign-in, remembered sessions, and passkeys

Sign-in uses Google OpenID Connect, so the identity provider verifies ownership of the email address. Email/password registration and login are not available. Sessions last up to 90 days and extend as the user continues using Daymark; set `DAYMARK_SESSION_DAYS` to choose a value from 7 to 365 days.

After signing in, open **Reminder** settings and choose **Set up a passkey**. The phone or computer will ask for Face ID, Touch ID, fingerprint, or device screen-lock verification. Daymark receives a public key, never biometric data. After the session expires, choose **Continue with passkey** on the sign-in screen. Passkeys require HTTPS on phones; localhost is treated as secure only on the same device. Configure `DAYMARK_WEBAUTHN_RP_ID` to the HTTPS site hostname when deploying behind a reverse proxy, and use `DAYMARK_WEBAUTHN_ORIGIN` only when the request's external origin cannot be detected automatically.

Google sign-in uses server-side OpenID Connect via Authlib. In Google Cloud Console, configure the authorized redirect URI to match the URL used to open Daymark. For local passkey development, add `http://localhost:8000/api/auth/google/callback`; keep any existing `127.0.0.1` callback if you still use that address for non-passkey testing. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. The exact redirect must match the host and scheme. Set a persistent random `DAYMARK_OAUTH_SESSION_SECRET`; set `DAYMARK_COOKIE_SECURE=1` when serving over HTTPS.

To enable background web push, install the declared `pywebpush` dependency, generate a VAPID key pair (the `vapid --gen` command is documented in the [py-vapid guide](https://github.com/web-push-libs/vapid/blob/main/python/README.rst)), and set `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, and `VAPID_SUBJECT` before starting Uvicorn. `VAPID_PUBLIC_KEY` must be the URL-safe `applicationServerKey` value, not the PEM file. Keep the private key on the server. Push requires HTTPS outside localhost.

## Working in this prototype

- Sign in with a verified Google account, then add, edit, and delete dated Work, Certification, and Award / recognition entries.
- Optionally attach a project, an outcome, and a highlight flag.
- Filter/generate a date-range appraisal narrative and inspect its supporting entries.
- Edit and save narrative drafts to the account, download a Word-compatible document, or print/save as PDF.
- Configure daily, weekday, or selected-day reminder preferences; this build can show browser notifications while open.
- User data is stored in SQLite and every data query is scoped to the signed-in account.
- Use the responsive layout on desktop and phone-sized screens.

## Prototype boundaries

This is an early local backend, not a production deployment. Google OpenID Connect sign-in, passkeys, server sessions, per-user SQLite entries and saved drafts, synced reminder preferences, and summary generation are implemented. In mock mode, summaries are assembled locally from saved entry fields; in Gemini or OpenAI mode, only entries in the selected date range are sent to the configured provider. Keep provider keys out of browser code. Existing browser-only entries can be imported into a new empty account after explicit confirmation.

Google sign-in requires provider credentials and callback configuration. Background web push is implemented but needs VAPID keys and an HTTPS deployment; without them, reminders only appear while the app is open. This is a responsive PWA, not separate native iOS/Android apps. Rate limiting, backups, and production database hosting also remain before launch. For production, enable secure cookies behind HTTPS and use a managed database with backups.

The Word export is an RTF document that Microsoft Word opens; PDF uses the browser's print dialog.
