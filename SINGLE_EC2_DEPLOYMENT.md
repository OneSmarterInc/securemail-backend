# Single EC2 backend and Vercel frontend: deployment order

> Audit storage decision — 2026-11-04: staff/admin activity logs remain in the same
> application PostgreSQL database on EC2. External audit archival code is removed; no audit bucket or second automatic
> audit copy is required. Earlier mandatory S3/Object Lock audit requirements are
> superseded. Database logs are not immutable against privileged administrators.
> Key-service security journals, recovery snapshots and cryptographic release
> gates remain separate and unchanged. See [DATABASE_AUDIT.md](DATABASE_AUDIT.md).


**Installation sequence:** use [AWS_FROM_SCRATCH.md](AWS_FROM_SCRATCH.md) for the current native AWS commands. The detailed sections below are reference material; do not mix their historical paths with the current procedure.

**Current account model:** all four Secure Mail processes use `ubuntu`. PostgreSQL, Redis and nginx retain their system accounts. Existing installations must follow [the single-user migration](SINGLE_USER_DEPLOYMENT.md). This supersedes earlier separate-OS-user claims; key-service paths remain unchanged and custodian unseal stays manual.


Current EC2 startup: [one-command startup and installation guide](ONE_COMMAND_AWS_STARTUP.md). The native units now use `/var/www/securemail-backend/current` and `/var/www/securemail-backend/venv`; `onesmarter.target` starts the stack while custodian unseal remains manual. This guide supersedes older executable paths and individual startup commands below.


Updated 2026-11-04. Selected layout: one Ubuntu EC2 instance for nginx, Django,
Celery, PostgreSQL, Redis and the sealed key service; Vercel for React. No private
DNS service or second key EC2 instance is required. This guide supplements the
full commands and PKI procedures in COMPLETE_DEPLOYMENT_GUIDE.md; it does not
claim that this machine has been deployed or approved for confidential data.

## 1. Prepare the instance and public names

Use a persistent data volume and a stable public ingress address. Confirm your
frontend, API and custody hostnames before issuing certificates. The examples are
`securemail.onesmarter.com`, `securemailbackend.onesmarter.com` and
`custody.onesmarter.com`. Create public DNS for API/custody at your existing DNS
provider; later use Vercel's exact records for the frontend. Do not buy or create
a DNS zone for `keys.internal`.

EC2 security group: allow HTTPS 443 for approved API clients, SSH only from your
administrator network (or use SSM). Restrict the custody virtual host additionally
to your approved operator/VPN addresses in nginx. A shared port-443 security group
cannot distinguish API and custody by hostname. Do not allow inbound 8443, 5432
or 6379. PostgreSQL/Redis must listen only locally in this arrangement.

## 2. Install accounts, directories and locked runtimes

Follow sections 7–9 of COMPLETE_DEPLOYMENT_GUIDE.md on this ONE instance. Create
one `ubuntu` system user for all four application services. Keep app data under
`/var/lib/onesmarter` and key data/accounts under `/var/lib/onesmarter-key`.
The shared UID can access the store, server private key and custodian credential
files. Keep recovery secrets off-host; this model removes separate-user isolation.

Install the backend release into the root-owned source location:
`/var/www/securemail-backend/current`. Runtime users must not
be able to replace executable source. Build/install the approved PQ-capable
Python/OpenSSL environment and hash-locked dependencies at the documented venv
paths. The repository's deploy/Dockerfile.pq identifies the tested runtime;
a stock Ubuntu Python is not evidence of PQ support. Do not weaken the transport
requirements if the runtime fails validation. Build artifacts on a larger
machine rather than compiling on the 1.3 GB instance.

## 3. Configure localhost name resolution

Inspect existing mappings first:

```bash
grep -n 'keys.internal' /etc/hosts
```

Edit with `sudoedit /etc/hosts`. Replace any old mapping for this name, preserving
all unrelated entries; do not append duplicates:

```text
127.0.0.1 keys.internal
```

Verify:

```bash
getent ahostsv4 keys.internal
```

Every returned address must be 127.0.0.1. This profile is native systemd, not
bridge-network containers. Do not enable PrivateNetwork on these units.

## 4. Provision PKI, key store and custodians

Follow sections 10–14 of COMPLETE_DEPLOYMENT_GUIDE.md and PRODUCTION_STARTUP.md
in the backend repository, in this order:

1. Provision the server certificate with SAN `DNS:keys.internal` and its private
   key for `onesmarter-key`; use an approved private CA.
2. Provision distinct scoped workload and custody-gateway client certificates.
   The app must not possess the gateway identity or CA signing key.
3. Initialize the key store ONCE as `onesmarter-key`, using the interactive
   off-host recovery-secret process. Never initialize over an existing store.
4. Independently retain the initial trusted checkpoint and encrypted backup;
   install its protected local checkpoint copy as documented.
5. Register scoped certificate identities and create named custodian accounts
   using the documented CLI. Keep account directories and policy paths consistent.

Same-machine storage does not replace off-host recovery, backup or independent
checkpoint custody. Do not keep the unseal secret in an environment file.

## 5. Configure backend and key-service environments

Use deploy/aws.env.example for `/etc/onesmarter/backend.env`; fill all required
settings through the protected deployment process. Follow the complete guide's
environment loader for migration/management commands. In particular:

```dotenv
KEY_PROTECTOR=key-service
KEY_SERVICE_URL=https://keys.internal:8443
KEY_SERVICE_CA=/etc/onesmarter/pki/key-service-ca.pem
KEY_SERVICE_CERT=/etc/onesmarter/pki/workload.pem
KEY_SERVICE_KEY=/etc/onesmarter/pki/workload.key
PQ_TRANSPORT_REQUIRED=true
DJANGO_READ_DOT_ENV=false
```

Set PUBLIC_URL, RECIPIENT_PUBLIC_URL, CORS_ALLOWED_ORIGINS and
CSRF_TRUSTED_ORIGINS to the confirmed frontend origin; ALLOWED_HOSTS names the API
host. Configure actual PostgreSQL, Redis, independent application secrets,
persistent storage and required audit archive settings. SMTP credentials belong
in the existing protected staff setup flow. Do not copy secrets into this guide.

Create `/etc/onesmarter-key/service.env` with the restricted runtime settings in
PRODUCTION_STARTUP.md. Match `KEY_SERVICE_CUSTODIAN_DIRECTORY` to
`/var/lib/onesmarter-key/accounts` in every applicable management/runtime context.
Key runtime and app environment files are separate; do not copy the entire app
environment to the key service. Complete release-gate review separately from
configuration validation.

## 6. Install the localhost key service

Run from the installed backend source directory after checking the unit's origin
and PKI paths. The committed unit already uses `--host 127.0.0.1`:

```bash
sudo install -m 0644 deploy/onesmarter-keyservice.service /etc/systemd/system/onesmarter-keyservice.service
sudo systemctl daemon-reload
sudo systemctl enable --now onesmarter-keyservice
sudo systemctl status onesmarter-keyservice --no-pager
sudo ss -ltnp 'sport = :8443'
```

The listener must be ONLY `127.0.0.1:8443`. The service starts sealed; this is
expected. Do not change the bind address to make remote browsers reach it.

## 7. Configure nginx and the custody gateway

Install the API nginx configuration and the exact maintenance-route gateway
contract in sections 15–16 of COMPLETE_DEPLOYMENT_GUIDE.md. The API proxies to
`/run/onesmarter/app.sock`. The maintenance gateway on the SAME EC2 proxies only
approved maintenance routes to `https://keys.internal:8443`.

The custody gateway still needs its reviewed configuration: the API example is
not a ready-made custody gateway. Keep its client certificate, upstream CA
verification, `proxy_ssl_name keys.internal`, SNI, PQ TLS policy, operator IP
restrictions, cookie path rewrite and method/path allowlist. Never proxy public
wrap/unwrap/import endpoints. Keep its gateway private key inaccessible to the
application user. Validate `sudo nginx -t` before reloading nginx.

## 8. Start the app services and initialize the workspace

With the correct app environment loaded, run the documented migration,
`manage.py check --deploy`, first-admin bootstrap and organization-key procedures
in section 16. Then install API/worker/beat units:

```bash
sudo install -m 0644 deploy/onesmarter-api.service /etc/systemd/system/onesmarter-api.service
sudo install -m 0644 deploy/onesmarter-worker.service /etc/systemd/system/onesmarter-worker.service
sudo install -m 0644 deploy/onesmarter-beat.service /etc/systemd/system/onesmarter-beat.service
sudo systemctl daemon-reload
sudo systemctl enable --now onesmarter-api onesmarter-worker onesmarter-beat
```

Before starting on a small machine, optionally install deploy/low-memory drop-ins
and the 5 MiB upload cap exactly as LOW_MEMORY_DEPLOYMENT.md describes. The key
service consumes additional RAM: 1.3 GB is not certified sufficient. Keep only
one beat instance. Do not change runtime user/group permissions to bypass errors.

## 9. Deploy the frontend on Vercel

1. Import `OneSmarterInc/securemail-frontend`; select the intended release branch.
2. Root directory `.`, framework Vite, Node 24, install `npm ci`, build
   `npm run build`, output `dist`.
3. Set these public build-time values to the confirmed addresses:

   ```dotenv
   VITE_BACKEND_URL=https://securemailbackend.onesmarter.com
   VITE_MAINTENANCE_URL=https://custody.onesmarter.com/maintenance/
   ```

4. Add the frontend custom domain and apply only the DNS records Vercel provides.
5. Deploy, then verify direct reloads of `/staff/` and `/recipient/`.
6. Ensure frontend origins match backend CORS/CSRF settings exactly. Changing
   VITE variables requires rebuilding. Never put SMTP passwords, CA private keys,
   recovery secrets or database credentials in Vercel frontend variables.

The maintenance page is served by the EC2 key service through the restricted
gateway, not a second Vercel application. Users outside the operator network
must not be able to access it.

## 10. Unseal and verify before use

Access the restricted custody page, sign in with the named custodian account,
complete MFA setup and unseal with the off-host secret. Configure organization
SMTP and staff sender credentials through the portal.

Perform the actual PQ endpoint test from section 19 using the workload CA and
certificate. Test staff login/MFA, recipient OTP, upload, reply and download.
Compare downloaded bytes to the original. Seal the key service and verify new
protected reads/downloads fail, then unseal and verify recovery. Already viewed
content or downloaded copies cannot be recalled by sealing.

Check service restarts, SMTP queue delay, host free RAM and peak process/cgroup
usage during concurrent uploads and large retained-file downloads. Repeat after
reboot: key service must start sealed. Test an off-host backup restore separately.
Local tests and successful CI are not live deployment or independent review.

## Rollback and operating boundary

Retain the previous release and configuration before deploying. Back up the
application database, encrypted documents, key store and independently held
checkpoint as a coordinated set. Do not replace/reinitialize an existing key
store to fix startup. A compromised host root can affect both app and key service;
the shared UID does not provide OS-user isolation.
