# Gmail automatic scanning setup

The Gmail integration uses Google's OAuth web-server flow and requests the read-only `gmail.readonly` scope. The initial scan lists up to 100 message IDs per page, fetches full messages in batches of up to 50, and can continue through the full inbox; later scans use a per-account time checkpoint to follow new inbox messages. Each unique new or changed message can result in a sequential Gemini request. Exact duplicate assessments and unchanged message fingerprints are reused. Consider the mailbox size and active Gemini quota before starting a first scan. The scanner stores detections in this app's history and does not change mailbox messages. Message IDs prevent repeat detections.

## One-time Google Cloud setup

1. Create or choose a project in [Google Cloud Console](https://console.cloud.google.com/).
2. Enable the Gmail API.
3. Configure the Google Auth Platform OAuth consent screen. For local development, use External / Testing and add your Gmail address as a test user.
4. Create an OAuth client ID of type **Web application**. Add the exact local callback URI you use in your browser. For example, if you open the app at `http://127.0.0.1:5000`, add:
   `http://127.0.0.1:5000/gmail/oauth/callback`
   If you open it at `http://localhost:5000`, add `http://localhost:5000/gmail/oauth/callback` instead. Google requires the redirect URI to match exactly.
5. Copy the client ID and client secret into a local `.env` file based on `.env.example`.
6. Generate a Fernet key and set `GMAIL_TOKEN_ENCRYPTION_KEY` in `.env`:
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
7. Set `FLASK_SECRET_KEY` to a separate long random secret. Never commit `.env` or share either secret.

The `gmail.readonly` permission is a restricted Gmail scope. Google may require OAuth app verification and additional security review before this can be offered broadly outside test users. See Google's [scope requirements](https://developers.google.com/workspace/gmail/api/auth/scopes) and [OAuth web-server flow](https://developers.google.com/identity/protocols/oauth2/web-server).

The OAuth callback stores the Gmail token encrypted with `GMAIL_TOKEN_ENCRYPTION_KEY`; refreshed credentials are encrypted before storage again. Disconnecting removes the app's stored token but does not revoke Google's OAuth grant. Revoke the grant in the Google Account security page if you want to remove that authorization. The project test suite mocks provider calls and does not verify OAuth consent or access to a real mailbox.

## Run locally

Install the project packages and start the app:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Running `.\.venv\Scripts\python.exe app.py` starts the scanner worker alongside Flask. Leave this PowerShell window open for automatic checks. Press **Ctrl+C** in that window to stop both Flask and its scanner. The app already starts an embedded worker, so do not start `gmail_worker.py` alongside it.

Open `http://127.0.0.1:5000`, sign in, and select **Connect Gmail** to authorize your account. A newly connected account is automatically scanned; use **Scan inbox now** for an additional manual scan. Automatic scans run about every three minutes and can be disabled at any time with the per-account toggle. The scanner lists up to 100 inbox message IDs per page, fetches full messages in Gmail API batches of no more than 50, and resumes historical scans from a cursor committed only after a complete page succeeds. Existing fingerprints and successful identical assessments avoid repeat Gemini calls. Gemini requests remain sequential because the project's active model quota cannot be determined from local configuration; repeated provider timeouts defer remaining messages for a later retry. The status view reports attempted, classified, failed, and deferred counts. A MongoDB lease prevents repeated clicks or scheduled workers from scanning the same account at once. Disabling automatic scanning takes effect during the current cycle as well as future cycles.

For local HTTP development, OAuthlib's insecure-transport allowance is enabled only during the authorization-code exchange when the callback host is `localhost` or a loopback IP. The setting is restored immediately afterward. Remote HTTP callbacks are not allowed by this code path; deployed callbacks should use HTTPS. OAuth state validation remains required.

Analyzed Gmail messages are saved in Atlas history with their extracted body. Only Fraudulent results from incremental scans create a MongoDB-backed in-app warning; the initial historical scan does not create notifications, and Safe results never create fraud alerts. The warning is saved atomically with the detection after analysis, with its detection time and saved explanation. The unique user/message index prevents duplicate records and alerts after scan retries or worker restarts. Warnings are private to the Gmail connection's user, can be marked read, and link to the matching history entry. The **Explain Result** section reuses the saved analysis explanation; opening it does not send the email to Gemini again.

Dashboard notifications work without browser permission. To receive optional desktop alerts, select **Enable desktop alerts** on the dashboard and grant browser permission. Alerts use a generic message without the subject, classification, sender, or body. While the dashboard is open it checks for unread alerts once per minute; each alert links to the matching history entry. Disable browser notifications later in your browser's site settings.

If Google expires or revokes the authorization, the app pauses automatic scanning for that account and shows that it needs to be reconnected. Use **Reconnect Gmail** to authorize it again. Temporary errors and quota responses are recorded as safe error categories in the connection status; provider response text and credentials are not shown. A scan is read-only and never sends, deletes, labels, or changes messages.

Disconnect Gmail in the app to stop future scans for that user. This removes the app's stored token and scan preference; users can also revoke the app from their Google Account security settings. Reconnecting creates a fresh encrypted token. The automatic scanner must run in the Flask process or in the separately managed worker described above.
