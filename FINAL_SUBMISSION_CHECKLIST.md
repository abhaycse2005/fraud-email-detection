# Final Submission Checklist

## Setup and configuration

- [ ] Use Windows with Python 3.12 and open PowerShell in this project directory.
- [ ] Install dependencies in the existing project virtual environment:

  ```powershell
  .\.venv\Scripts\python.exe -m pip install -r requirements.txt
  ```

- [ ] Keep secrets in the project-root `.env`; do not share or commit it. `.env` is ignored by `.gitignore`, and it is not tracked in the current Git index. `.env.example` contains placeholders and setup comments, not usable credentials.
- [ ] Ensure a reachable MongoDB Atlas cluster and valid database user are configured. Atlas TLS verification stays enabled and uses certifi.
- [ ] Ensure the configured Gemini API key has permission and quota for `gemini-3.1-flash-lite`.
- [ ] Gmail is optional. For Gmail, configure Google OAuth, the token-encryption key, the matching local redirect URI, and the read-only Gmail scope.
- [ ] Before starting Flask, confirm whether a previously connected Gmail account has automatic scanning enabled. The embedded worker can scan after successful database initialization; use a demo mailbox and disable auto-scan when appropriate.

## Features present in the existing project

- Login, registration, session security, CSRF protection, and user-scoped data access.
- Dashboard, manual email analysis, CSV analysis, Safe/Suspicious/Fraudulent results, Explain Result, and detection history.
- MongoDB Atlas persistence for users, detections, notifications, and encrypted Gmail connection tokens.
- Optional read-only Gmail OAuth, paginated message listing, bounded Gmail batch fetching, duplicate/fingerprint reuse, scan leases, progress reporting, and failed/deferred message retry behavior.
- Gemini errors, invalid responses, timeouts, provider errors, and quota failures are handled without inventing a Safe assessment.

## Main dependencies

Flask/Werkzeug, PyMongo, dnspython, certifi, python-dotenv, google-genai, Google OAuth and Gmail API client packages, cryptography, requests, joblib, scikit-learn, and NumPy. The project requirements are in `requirements.txt`.

## Local verification performed

- Full pytest suite: **123 passed, 50 subtests passed**. Pytest emitted 15 warnings: NumPy/joblib deprecation warnings and a Windows access-denied warning while writing the pytest cache; no test failed.
- Python compilation (`compileall` over application, support scripts, model, and tests): **passed**.
- Dependency consistency (`pip check`): **passed; no broken requirements found**.
- Flask import and compilation of the base, login, registration, dashboard, analysis, history, Gmail, account-security, admin, and unavailable-service templates: **passed**.
- Route, authentication, user-isolation, classification, Gemini failure/retry, Gmail checkpoint/progress/retry, and persistence behavior are covered by the local mocked test suite.
- JavaScript syntax check: **not run** because Node.js is unavailable in this environment.

## Live service checks and current blockers

- MongoDB Atlas: a read-only ping using the configured standard URI, TLS verification, and certifi failed at the network/server-selection stage. No database records were modified. This does not establish whether the cause is DNS, outbound network/firewall, Atlas access-list reachability, or service availability.
- Gemini: one minimal harmless request using the configured model failed with the sanitized category `connection_failure` (`ConnectError`, no HTTP status). This indicates a connection-stage failure; it does not establish a quota or authentication failure.
- Gmail OAuth and mailbox scanning: **not live-tested**. No authorization flow or scan was started. Do not claim these integrations work until tested with the intended demo account after Atlas and Gemini connectivity are restored.
- The actual Flask `app.py` startup command was not launched because startup requires Atlas and starts the embedded Gmail scanner after Atlas initialization. Local import and route tests passed, but service-backed startup is currently blocked by the Atlas connection failure.

## Known limitations

- The project cannot currently complete a live demonstration in this environment until Atlas and Gemini network connectivity is restored and retested.
- Gemini quotas depend on the configured Google project/account. This project does not increase concurrency based on assumed quota.
- Gmail authorization, consent-screen status, live mailbox access, and long-running scan behavior remain unverified here.
- The local machine-learning artifact is not used for live manual analysis; new analysis requires Gemini. Model evaluation and dataset limits are documented in `README.md`.
- The Flask development server is for a local demonstration, not public deployment.

## Startup and demo sequence

From the project root in PowerShell:

```powershell
.\.venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5000`, register or log in using the intended demo account, then demonstrate manual analysis with synthetic email text. Verify the saved record in Detection History. Demonstrate Gmail only after confirming Atlas/Gemini connectivity, OAuth consent, read-only scope, and a suitable demo mailbox. The broader step-by-step instructions are in `DEMO_GUIDE.md` and `GMAIL_SETUP.md`.

## Submission decision

**Current status: NOT READY for a live end-to-end demo.** Local code and test checks passed, but the read-only Atlas ping and Gemini connectivity request both failed. Recheck those services on the network where the project will be demonstrated; do not present unverified Gmail scanning as working.
