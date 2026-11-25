# Automatic MongoDB Atlas IP allowlist update (Windows)

The normal Flask startup remains Atlas-only. IP allowlist updates are a separate
pre-start operation and happen only when you run the PowerShell launcher.

## Atlas API credentials

1. In Atlas, open the project that contains the `FraudEmailDetection` cluster.
2. Create a project API key under **Project Access / API Keys**. Scope it to this
   project only, and assign **Project Network Access Manager** (or the
   equivalent **Project IP Access List Admin** role shown by your Atlas UI).
   The updater only reads this project's access list and adds an entry; it does
   not need organization-wide access, database-user permissions, or cluster
   management permissions.
3. Copy the API public key and private key once. Treat both as credentials.
4. Find the project ID in Atlas Project Settings. It is a 24-character ID.
5. Add these names to the existing `.env` file with your own values; do not put
   values in source control or share them:

   ```dotenv
   MONGODB_ATLAS_PUBLIC_KEY=<atlas-api-public-key>
   MONGODB_ATLAS_PRIVATE_KEY=<atlas-api-private-key>
   MONGODB_ATLAS_PROJECT_ID=<24-character-atlas-project-id>
   ```

   Keep the existing `MONGODB_URI` database connection setting as it is. The
   Atlas API keys are separate from the MongoDB database username/password.

## Run on a Windows/Jio hotspot

From the project directory in PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\run_with_atlas_ip_update.ps1
```

The leading space before `.` is optional. The launcher detects the current
public IPv4 through an external IP lookup service, reads the configured
project's access list, and adds only that address as an individual `/32` when
not already covered. It reads the list again to verify the change. If detection,
Atlas authentication, permission, network access, or verification fails, the
launcher stops without starting Flask. It never removes existing entries and
never adds `0.0.0.0/0`.

When your Jio hotspot public IP changes, run the launcher again. If your mobile
provider uses carrier-grade NAT or changes the public egress IP while the app is
running, restart the launcher after the change. Atlas may take a short time to
apply a newly added entry.

To run the updater alone without starting Flask:

```powershell
.\.venv\Scripts\python.exe .\atlas_ip_allowlist.py
```

To start Flask manually, without invoking the updater:

```powershell
.\.venv\Scripts\python.exe .\app.py
```

Manual Flask startup still requires the machine's IP to already be allowed in
Atlas. The application's existing Atlas connection retries and fail-safe
behavior remain unchanged.

## Troubleshooting and revocation

- **Public IP lookup timeout/invalid response:** check internet access, then retry.
- **401/403:** verify that the API key is active and has the project IP access
  list role on the exact project ID. Do not share the key values.
- **404/project mismatch:** verify the configured project ID and API key scope.
- **Atlas connection DNS/timeout after updater succeeds:** check Atlas cluster
  status, database user credentials in `MONGODB_URI`, DNS, and any firewall or
  provider restrictions. The updater changes only the Atlas access list.
- Revoke the API key from Atlas Project Access / API Keys if it is exposed or
  no longer needed, then remove its two values from the private `.env` file.
  Existing allowlist entries are not automatically removed.

The project ID and API keys are not sent to the browser. Requests use bounded
timeouts and logs do not include API credentials or raw provider error bodies.
