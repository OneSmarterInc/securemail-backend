# Production startup configuration

**Current account model:** all four Secure Mail processes use `onesmarter`. PostgreSQL, Redis and nginx retain their system accounts. Existing installations must follow [the single-user migration](SINGLE_USER_DEPLOYMENT.md). This supersedes earlier separate-OS-user claims; key-service paths remain unchanged and custodian unseal stays manual.


Current EC2 startup: [one-command startup and installation guide](ONE_COMMAND_AWS_STARTUP.md). The native units now use `/var/www/securemail-backend/current` and `/var/www/securemail-backend/venv`; `onesmarter.target` starts the stack while custodian unseal remains manual. This guide supersedes older executable paths and individual startup commands below.


Updated 2026-11-04 at the owner's request. Production and staging now start when
their configuration is valid. The unconditional Django and key-service refusals
are removed. This change is not independent cryptographic approval or evidence
that AWS has been deployed. See RELEASE_GATES.md for outstanding acceptance work.

## What stays enforced

- Explicit `APP_ENV=production` or `staging`; no automatic development fallback.
- Django: PostgreSQL, explicit Redis, independent application secrets, HTTPS
  public URLs, exact host/origin allowlists, restricted Unix-socket proxy profile,
  private persistent storage and an audit archive configuration.
- Remote key service with real PQ TLS support and client certificates. Secure
  cookies, HTTPS redirect and HSTS are enabled. No local-key fallback.
- Key service: existing trusted checkpoint verified before listening, mandatory
  mutual TLS and PQ negotiation, backup directory, scoped certificate policy,
  and sealed startup. Custodian authentication and unseal are still required.
- Development tools, legacy synthetic reads/import, classical/HTTP escape flags
  and the experimental audit candidate are forbidden in production.

## Important audit boundary

The supported production startup path uses the existing legacy store format and
an independently protected trusted checkpoint. Its audit chain uses unkeyed
SHA-256. The checkpoint detects changes to the anchored prefix, but is not a
continuous external signed log: a store writer can coherently rewrite the tail
after the anchor, and rollback to an unanchored later state may go undetected.
Protect and periodically advance checkpoints through a separately administered
process after verifying the intervening history. Do not automatically replace a
trusted checkpoint with whatever a potentially compromised store exports.

The HMAC/Ed25519 checkpoint candidate remains restricted to synthetic use. This
change does not resolve RP-04/RP-05 for real-data deployment. Real-data approval
requires acceptance/remediation of this limitation and the independent review.

## 1. Prepare the application environment

Use `deploy/aws.env.example` as the template for `/etc/onesmarter/backend.env`.
Fill all empty required settings. Generate three different high-entropy secrets
for `DJANGO_SECRET_KEY`, `DOCUMENT_INTEGRITY_KEY` and `SEARCH_INDEX_KEY`; each must
be at least 32 characters. Keep them stable across restarts and back them up
securely. Never put these secrets in a frontend `VITE_` variable.

Configure real `AWS_REGION`, `AUDIT_BUCKET` and positive `AUDIT_RETENTION_DAYS`,
and separately provision/verify archive retention and permissions. These startup
checks do not prove that an external bucket, database or SMTP account works.
Private file storage remains EBS (`STORAGE_PROVIDER=local`); no AWS KMS is needed.

Set the real frontend origin in PUBLIC_URL, CORS_ALLOWED_ORIGINS and
CSRF_TRUSTED_ORIGINS. KEY_SERVICE_URL must resolve privately and its certificate
SAN must match. KEY_STATUS_* may use their documented workload defaults or a
separately authorized status identity. All referenced certificate files must
exist and be readable by the service identity. Use the project's tested PQ
Python/OpenSSL runtime, not an arbitrary distribution Python build.

Run migrations/checks with this environment loaded as described in the complete
guide. They also enforce these startup requirements. Do not switch to development
to work around a configuration error.

## 2. Initialize the key store once

Complete the OS users, directories and PKI steps in COMPLETE_DEPLOYMENT_GUIDE.md
first. The following paths match that guide. Run on the key host:

```bash
cd /opt/onesmarter-key/current
sudo -u onesmarter env APP_ENV=production \
  /opt/onesmarter-key/venv/bin/python -m backend.keyservice init \
  --store /var/lib/onesmarter-key/store.sqlite3
```

The command asks twice, without echo, for the 32-byte base64 recovery secret
generated and retained on a separate custodian device. It does not generate a
production recovery-secret file on the server. Do not reinitialize an existing
store. A new legacy store now records an initialization event so it can export
its first checkpoint before serving requests.

Export the initial checkpoint while you control the newly initialized store:

```bash
sudo -u onesmarter env APP_ENV=production \
  /opt/onesmarter-key/venv/bin/python -m backend.keyservice checkpoint \
  --store /var/lib/onesmarter-key/store.sqlite3 \
  --destination /var/lib/onesmarter-key/initial-checkpoint.json
sudo install -d -o root -g onesmarter -m 0750 /etc/onesmarter-trust
sudo install -o root -g onesmarter -m 0640 \
  /var/lib/onesmarter-key/initial-checkpoint.json \
  /etc/onesmarter-trust/checkpoint.json
```

Independently retain and verify this checkpoint off-host, together with the
corresponding store backup. The local protected copy alone does not survive a
root compromise. The staging export is not the trust source on later starts.
Never accept an arbitrary existing store's newly exported checkpoint as proof
that its history was authentic. Existing stores need a verified existing anchor.

## 3. Register identities and custodians

Follow the exact PKI/policy and `python manage.py custodian create` commands in
COMPLETE_DEPLOYMENT_GUIDE.md. The key service needs a workload identity, a gateway
identity and individual custodian accounts. A client certificate alone is not a
human login. First login sets a password and enrolls TOTP. The Django-based
custodian CLI still needs the complete management environment; the small runtime
key-service environment below is not sufficient for that management command.

## 4. Start the native key service

Create `/etc/onesmarter-key/service.env` with restricted permissions:

```dotenv
APP_ENV=production
SYNTHETIC_MODE=false
KEY_SERVICE_CUSTODIAN_DIRECTORY=/var/lib/onesmarter-key/accounts
```

The selected single-EC2 profile in `deploy/onesmarter-keyservice.service` binds
only `127.0.0.1:8443`. Map `keys.internal` to `127.0.0.1` in `/etc/hosts` and match
certificate paths to your PKI. Do not add a security-group ingress rule for 8443.
The unit keeps mTLS/PQ verification and does not use `--synthetic-only`.
See SINGLE_EC2_DEPLOYMENT.md for the ordered setup and localhost checks.

```bash
sudo install -m 0644 deploy/onesmarter-keyservice.service \
  /etc/systemd/system/onesmarter-keyservice.service
sudo systemctl daemon-reload
sudo systemctl enable --now onesmarter-keyservice
sudo systemctl status onesmarter-keyservice --no-pager
```

The service starts **sealed**. Configure the private custody gateway, open its
HTTPS page, authenticate as a custodian and supply the off-host unseal secret.
The app must report the document service disabled until readiness succeeds.
Do not put the recovery secret in systemd, shell arguments or environment files.

## 5. Start the app and verify the full deployment

Use the API/worker/beat units and nginx instructions in the complete guide.
The Vercel app is one React frontend; the maintenance UI is separately served by
the key service through the restricted AWS custody gateway. It is not a second
Vercel deployment. Configure the public frontend URL only after confirming DNS.

Verify migrations, `manage.py check --deploy`, strict TLS on actual endpoints,
sealed/unsealed readiness, staff and custodian MFA, recipient upload/read,
SMTP delivery, checkpoint custody, off-host backup and a clean-machine restore.
Local startup tests do not replace those deployment checks. No cloud services
were provisioned or enabled by this code change.

## Local verification for this change

- Complete backend regression suite, Windows/Python 3.12 with isolated test data:
  **580 passed, 17 skipped**. Skips are not production evidence.
- Focused startup/environment/escape-flag tests using the actual Python 3.15 /
  OpenSSL PQ runtime: **59 passed**, including real production Django startup,
  sealed production key-service startup with PQ mTLS, and classical TLS rejection.
- Ruff check and formatting check passed; migration drift check reported no changes.
- CI includes the new real-runtime startup tests in the PQ transport job.
- AWS/Vercel runtime deployment, external crypto review and remote restore drills
  were not performed by this change. See CI for the pushed commit's separate result.
