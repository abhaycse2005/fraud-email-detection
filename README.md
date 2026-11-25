# Fraud Email Detection

Flask application for single and CSV email analysis, account history, a dashboard, and optional read-only Gmail scanning. New analysis requests use Google's Gemini Developer API; detection records, users, and Gmail connection data use MongoDB Atlas.

For step-by-step local setup and presentation guidance, see [DEMO_GUIDE.md](DEMO_GUIDE.md).

## Local setup

### Project structure

```text
app.py                 Flask routes, Gmail scanning, and result coordination
ai_analysis.py         Gemini request, response validation, and bounded retries
database.py             MongoDB Atlas persistence and user-scoped queries
gmail_worker.py         Optional standalone Gmail scanner process
model/                  Existing local model, vectorizer, metrics, and training script
dataset/emails.csv      Labeled examples used for the local model
templates/              Jinja pages
static/                 CSS, JavaScript, and demo CSV files
tests/                  Mocked integration, policy, and isolation tests
```

1. Install Python 3.12, then create and activate a virtual environment in PowerShell:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Create a MongoDB Atlas cluster and database user, add this computer's IP to the Atlas access list, and copy the **Drivers** URI. URL-encode special characters in the database password.
4. Copy `.env.example` to `.env` and set these values locally:
   - `FLASK_SECRET_KEY`: random secret of at least 32 characters.
   - `MONGODB_URI`: Atlas connection URI.
   - `GEMINI_API_KEY`: Gemini Developer API key from [Google AI Studio](https://aistudio.google.com/).
   - `GEMINI_MODEL`: optional model ID; defaults to `gemini-3.1-flash-lite`. Choose a model enabled for this AI Studio project.
   - `GMAIL_TOKEN_ENCRYPTION_KEY`: optional until Gmail is connected; generate with the command below.
5. Start the app from PowerShell:

   ```powershell
   .\.venv\Scripts\python.exe app.py
   ```

   Generate a Fernet key for Gmail token encryption:

   ```powershell
   .\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   Open `http://127.0.0.1:5000`. MongoDB Atlas is required; startup stops with a sanitized connection error if Atlas cannot be reached. SQLite is not used by the running application. The existing `fraud_detection.db` file is left untouched.

Never commit `.env` or paste its values into issue reports. `.env` is ignored by Git. The Flask development server is for local use. For an HTTPS deployment set `SESSION_COOKIE_SECURE=1`, disable debug mode, and use a production WSGI server.

## Gemini analysis

The app uses `google-genai` and selects its model from `GEMINI_MODEL` (default `gemini-3.1-flash-lite`). It treats email fields as untrusted content, requests the same validated JSON schema for each selected model, and applies local sender, link, urgency, and sensitive-credential context. Gemini confidence is an estimate, not a calibrated probability; the displayed risk score is a severity scale from 0 to 100. An API failure does not result in a safe classification. API key, quota, model, connection, and timeout failures are logged by sanitized category. A configured model name does not establish that the key has access or available quota.


## Gmail setup

Gmail is optional and configured separately. Follow [GMAIL_SETUP.md](GMAIL_SETUP.md) to configure the Google OAuth client, redirect URL, read-only Gmail API scope, and token encryption. The app does not send or modify email. Gmail access has not been verified against a real account as part of this project review; OAuth consent, Google verification requirements, and the user's network still need to be checked in the local environment.

The web app starts one background scanner thread in its process after MongoDB initialization. A process-local guard prevents repeated startup calls from creating extra threads, and an Atlas lease prevents overlapping scans of the same account across processes. The initial scan lists up to 100 message IDs per page and fetches full messages in Gmail batches of no more than 50; each page's durable cursor advances only after every listed email succeeds. Existing fingerprints and exact duplicate assessments avoid repeat Gemini calls. Each unique new or changed message still needs a Gemini request, which remains sequential because the active project quota is not available in local configuration. Repeated provider failures defer remaining messages for retry. Review the connected mailbox and model quota before a first scan.

Automatic Gmail scanning is enabled when a new Gmail account is connected and can be disabled per account from **Connect Gmail**. Fraudulent results from incremental scans create private, unread dashboard notifications in Atlas and link to the matching history record; the initial historical scan does not generate alerts. Safe results never create fraud alerts. Marking a notification read updates only that user's record. Users can opt into generic browser alerts; they contain no email details and are checked once per minute while the dashboard is open. **Explain Result** shows the stored analysis explanation, or a conservative summary based on recorded signals for older records; it does not make another Gemini request. If authorization expires or is revoked, scanning pauses for that account until it is reconnected. See [GMAIL_SETUP.md](GMAIL_SETUP.md) for the full behavior and controls.

## Existing local SQLite data

The old `fraud_detection.db` is not queried by the app and is not deleted. If it contains records that have not been moved to Atlas, `migrate_sqlite_to_mongodb.py` is an explicit, one-time migration utility. Review it and back up the source first, configure Atlas, then run:

```powershell
.\.venv\Scripts\python.exe migrate_sqlite_to_mongodb.py
```

It opens the legacy file read-only and copies records to MongoDB. It is not part of application startup or runtime database access.

## Tests and model evaluation

Run the mocked/local automated tests with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q app.py ai_analysis.py database.py gmail_worker.py tests
.\.venv\Scripts\python.exe -m pip check
```

The equivalent pytest command is `python -m pytest -q`.

Unit tests mock Gemini, MongoDB, and Gmail network calls. They do not prove live service connectivity. A live Gemini request succeeds only when tested with a real configured key and working outbound network. Gmail OAuth requires a real user authorization and has not been exercised by the unit suite. This project has not been load-tested for 50 concurrent users. The embedded scanner runs sequentially in the Flask process, and the Flask development server is not suitable for concurrent production traffic. A multi-process deployment needs a separately managed single scanner worker, production WSGI configuration, Atlas/Gemini quota planning, and load testing; the current startup path should not be assumed safe to scale by adding web workers.

`dataset/emails.csv`, the model bundle, and `model/metrics.json` are preserved. The dataset has 127 unique labeled rows: 45 safe, 40 suspicious, and 42 fraudulent. The existing duplicate-aware held-out evaluation uses 95 training rows and 32 test rows. Its latest reproduced result is accuracy 65.62%, macro precision 82.54%, macro recall 66.67%, and macro F1 63.86%; with class order safe, suspicious, fraudulent, the confusion matrix is `[[8, 3, 0], [0, 10, 0], [0, 8, 3]]`. In particular, only 3 of 11 fraudulent test examples were labeled fraudulent, so this small dataset/model should not be treated as a reliable fraud detector. The held-out split was also used to select the candidate, so these scores are not an independent final estimate. New web analyses use Gemini, not the saved local model.

The training script writes over the model and metric artifacts. It is not run by the app or the tests; back up those files before intentionally retraining.

## Atlas IP allowlist on Windows

To detect a changed hotspot IP, update the configured Atlas project's allowlist, verify it, and then start Flask, follow [ATLAS_IP_SETUP.md](ATLAS_IP_SETUP.md) and run `.\run_with_atlas_ip_update.ps1` in PowerShell. This explicit launcher requires a project-scoped Atlas Administration API key; ordinary `.\.venv\Scripts\python.exe app.py` startup and the app's Atlas-only database behavior are unchanged.

## Local development and security notes

The red Werkzeug message saying its server is for development is expected when running the local Flask server. It is a warning, not an application failure. For this laptop-only college demo, leave it visible; do not set `WERKZEUG_RUN_MAIN` or suppress warnings. Flask debug mode defaults off and is controlled by `FLASK_DEBUG`.

Start Flask with the project's explicit virtual-environment interpreter. This avoids using a different system Python when the shell or IDE has not activated `.venv`:

```powershell
.\.venv\Scripts\python.exe app.py
```

To confirm which interpreter a terminal command resolves to, run `python -c "import sys; print(sys.executable)"`. For this project it should point inside `.venv\Scripts\python.exe`.

Use `.\run_with_atlas_ip_update.ps1` instead when you need to refresh the Atlas allowlist for a changed hotspot IP. Direct startup does not run the updater. Atlas remains required; if Atlas is unreachable, startup stops after its configured retries.

Browser POST requests now require a session-bound CSRF token, and logout is POST-only. Runtime PyMongo errors return a generic temporary-unavailable response and log only the exception type; they do not masquerade as duplicate-email or wrong-password results. Flask/Jinja template autoescaping is enabled; client-side analysis results use HTML escaping or DOM `textContent`. The session cookie is HttpOnly and SameSite=Lax. `SESSION_COOKIE_SECURE` stays off for local HTTP and must be set to `1` behind HTTPS.

## Before any public deployment

Deployment is not authorized or performed. Do not expose the Flask development server publicly. Before public access, obtain college permission and complete a deployment review: serve through a production WSGI server behind HTTPS; set `FLASK_DEBUG=0` and `SESSION_COOKIE_SECURE=1`; manage secrets outside source control; configure trusted proxy behavior and host restrictions; add authentication rate limiting and monitoring; decide on a single, separately managed Gmail worker for multi-process deployments; and test Atlas, Gemini, OAuth, backup, restore, and incident-revocation procedures in the chosen environment. The current app starts the Gmail scanner thread inside the web process, and Atlas initialization is in the script startup block. I did not add a WSGI entry point because that lifecycle needs to be separated first to avoid skipping database initialization or running duplicate scanners in multi-process deployments.

## Verification status

The automated suite uses mocks for MongoDB, Gemini, Gmail, and Atlas Administration API changes. It verifies user-scoped history, CSRF behavior, classification validation, and updater behavior without changing Atlas or a mailbox. The suite does not verify live Atlas connectivity, Gemini API access, Gmail OAuth/mailbox access, long-running worker behavior against live services, or persistence across a real Atlas restart. Run it with `python -m pytest -q`; compile and dependency checks are listed above. The model-evaluation caveats above still apply.
