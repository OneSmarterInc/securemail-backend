# Local maintenance route

Open **http://localhost:5173/maintenance/**. `/maintenance` redirects to the trailing-slash route. The staff portal remains at `/`.

The Vite development gateway forwards only the maintenance assets and custodian operations to the separate loopback key service. It authenticates with a dedicated gateway client certificate over PQ-only TLS. Custodian login remains separate from staff login. Browser cookies are HttpOnly, SameSite=Strict and scoped to `/maintenance/`; exact-Origin and CSRF checks remain enforced. The frontend build neither reads nor bundles private certificate files.

This is a **synthetic localhost preview**. Browser-to-Vite HTTP is not PQ transport. The service accepts that HTTP origin only through the explicit `--allow-http-loopback-origin` flag with a loopback service bind. Production still requires approved HTTPS, gateway identity/custody controls and the deployment gates. Sharing an origin means shared browser trust: a compromise of the app's frontend can affect maintenance. A URL path is not a separate browser security boundary.

## Local credentials

- Username: `custodian`.
- Initial password: `.runtime/maintenance-credentials/custodian-password.txt`.
- Unseal key: `.runtime/maintenance-credentials/unseal-key.txt`.
- Key store and Argon2id credential policy: `.runtime/maintenance/`.

These are synthetic development credentials, restricted to the current Windows account, excluded from Git and Docker build contexts, and not printed by setup. Move the initial password and recovery key to separate secure custody after setup. The initial password file is a delivery artifact; the actual login verifier is an Argon2id hash. Recovery keys and SMTP authentication secrets cannot be replaced with one-way password hashes because they must be used for cryptographic recovery or external authentication.

Staff passwords already use Django Argon2id. Existing PBKDF2 hashes remain verifiable and upgrade after successful authentication. Hashcat is not a storage hash algorithm and is not used.

## Start/restart

From the repository root, using the provisioned isolated PQ runtime:

```powershell
.runtime\pq-python315\python.exe scripts/start_local_maintenance.py
```

The script starts a hidden local service, preserves existing keys and refuses to replace a listener on port 8443. It starts sealed. Vite must run as the same Windows user with access to the restricted gateway certificate files. Normal Vite config reload picks up the route. For a genuinely new setup only, `scripts/init_local_maintenance.py` creates synthetic certificates, policy, encrypted store and initial credentials; it refuses existing directories to avoid losing recovery material. Certificates and gateway identity expire after 90 days.

The page controls this separate key-service store. Document sending is now gated by its authenticated readiness: sealing disables uploads, sends and replies, and holds queued conversation deliveries. See [SERVICE_READINESS.md](SERVICE_READINESS.md). The current development app still uses its existing `local-development` protector; moving existing documents to the service requires the verified import/migration procedure in `KEY_SERVICE_OPERATIONS.md`. Admission control does not silently migrate documents or replace their keys.

## Verification

Browser verification through `/maintenance/` passed login, unseal, cleared secret inputs, seal and logout. The service was left sealed. Password tests cover salted Argon2id, wrong-password rejection and PBKDF2 upgrade. The standalone HTTPS custodian route remains supported for certificate-equipped clients.
