# Daymark

**A private work journal that helps you remember what you accomplished.**

Daymark is a personal work log for employees preparing for performance reviews. Record work as it happens, mark important contributions as highlights, then choose a date range to create an editable appraisal narrative grounded in your entries.

## Try the hosted app

**https://daymark-uh3d.onrender.com**

> **Hosted data warning:** The current Render deployment does not have a persistent disk. Its SQLite database is stored on temporary service storage and can be lost when the service restarts, redeploys, or otherwise replaces that storage. The hosted app is for preview and experimentation; do not rely on it as the only copy of important work records. Keep a separate copy of anything you need to retain. Local development data is stored separately on your own computer.

The hosted service uses Render's free web service plan and may take a little time to wake after inactivity.

## What you can do

- Sign in with Google and keep a remembered session.
- Create, edit, and delete dated work, certification, and award or recognition entries.
- Add project and outcome details, and flag entries as highlights.
- Record work for earlier dates or leave days empty.
- Generate an editable summary for a selected date range, review its supporting entries, and save drafts.
- Export a draft to a Word-compatible document or print it to PDF.
- Set reminder preferences and enable browser push notifications when the service is configured for web push.
- Use passkeys on supported devices and browsers.

## Run locally

You need Python 3.10 or later. From the project directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp .env.example .env
uvicorn backend.main:app --reload
```

Open **http://localhost:8000**. The app and API are served from the same origin. The interactive API documentation is at **http://localhost:8000/docs**.

The local SQLite database is created as `daymark.sqlite3` in the project directory. To use another location, set `DAYMARK_DB_PATH` in `.env`. This database is independent of the hosted app's database.

## Configuration

Daymark reads configuration from environment variables. For local development, put them in `.env`; for a hosted deployment, set them in the hosting provider's service settings. Never commit `.env`, API credentials, OAuth secrets, or private key files.

### Google sign-in

Google sign-in requires OAuth credentials from Google Cloud Console. Set:

```env
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
DAYMARK_OAUTH_SESSION_SECRET=your-long-random-secret
```

Register the callback URL with Google, matching the exact scheme, host, and path. For local development, use:

```text
http://localhost:8000/api/auth/google/callback
```

For the hosted app, use:

```text
https://daymark-uh3d.onrender.com/api/auth/google/callback
```

Email-and-password sign-in is not available. Google verifies the account email during sign-in.

### AI summaries

Gemini is the default summary provider. Set:

```env
SUMMARY_MODE=gemini
GEMINI_API_KEY=your-gemini-api-key
GEMINI_MODEL=gemini-3.1-flash-lite
```

Only entries in the selected date range are sent for summary generation. The app extracts concise facts from entries in batches, then drafts appraisal-style paragraphs from those facts and retains source-entry references for review. AI-generated text should be checked and edited before use in a performance review.

Gemini free-tier availability, quotas, and data terms can change. Review [Gemini API pricing and data use](https://ai.google.dev/gemini-api/docs/pricing) before sending sensitive or confidential work information. For a local draft without an AI API call, set `SUMMARY_MODE=mock`; this formats recorded fields into paragraphs without AI paraphrasing. An optional legacy OpenAI mode is also available with `SUMMARY_MODE=openai`, `OPENAI_API_KEY`, and `OPENAI_MODEL`.

### Passkeys and secure cookies

For a hosted HTTPS deployment, set:

```env
DAYMARK_COOKIE_SECURE=1
DAYMARK_WEBAUTHN_RP_ID=your-site-hostname
```

`DAYMARK_WEBAUTHN_RP_ID` is the hostname only, without `https://` or a port. For this hosted app it is `daymark-uh3d.onrender.com`. Local passkey testing should use `localhost`; passkeys on phones require HTTPS.

Sessions last 90 days by default and extend with use. To choose a different duration, set `DAYMARK_SESSION_DAYS` to a number from 7 to 365.

### Push notifications

Background web push requires an HTTPS origin and a matching VAPID key pair:

```env
VAPID_PUBLIC_KEY=your-url-safe-application-server-key
VAPID_PRIVATE_KEY=/path/to/vapid_private.pem
VAPID_SUBJECT=mailto:you@example.com
```

`VAPID_PUBLIC_KEY` is the URL-safe application server key, not a PEM file. `VAPID_PRIVATE_KEY` points to the private key file; keep that file secret and outside the repository. The public and private keys must belong to the same pair. Without VAPID configuration, browser notifications may work only while the app is open, and background push is unavailable.

## Data and privacy

The app stores journal entries, saved drafts, and reminder preferences in SQLite, scoped to the signed-in account. Local and hosted installations use separate databases; signing in with the same Google account does not synchronize or migrate entries between them. The current hosted Render service has no persistent disk or database backup, so its data can be lost. This prototype does not provide a guaranteed backup or recovery system.

Keep API keys and OAuth credentials on the server. Do not add secrets to frontend code, commit them to GitHub, or include confidential employer information unless you have reviewed the AI provider's data terms and your employer's policies.

## Deployment notes

The app can run on a Python ASGI host with HTTPS. A typical Render configuration is:

- **Build command:** `pip install -r backend/requirements.txt`
- **Start command:** `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`

Set the required secrets and provider credentials in the host's environment settings. For a reliable production deployment, use a persistent managed database with backups and durable storage; the current hosted free deployment does not have a persistent disk. Background reminder scheduling may also be interrupted when a free web service sleeps.

## Project status

Daymark is an evolving personal project/prototype. It is a responsive web app and installable PWA, not a native iOS or Android app. Review generated summaries and keep independent backups of any work records you need.
