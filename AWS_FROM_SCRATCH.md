# Secure Mail: AWS installation from scratch

**Current account model:** all four Secure Mail processes use `onesmarter`. PostgreSQL, Redis and nginx retain their system accounts. Existing installations must follow [the single-user migration](SINGLE_USER_DEPLOYMENT.md). This supersedes earlier separate-OS-user claims; key-service paths remain unchanged and custodian unseal stays manual.


Updated 4 November 2026. One Ubuntu EC2, native systemd, PostgreSQL on EC2, no
Docker, one Secure Mail service account, one startup target and manual custodian unseal.
Frontend hosting is outside this AWS-only guide.

## Read this sequence first

| Order | What you prepare | Completion check |
|---|---|---|
| 1–3 | EC2, network, storage, native OpenSSL/Python/nginx | Verified runtime installed |
| 4–5 | One application account, source, venv, fresh secrets | Source readable; secrets private |
| 6 | Local PostgreSQL, Redis, keys.internal hosts entry | Database login succeeds |
| 7–9 | Service keys, off-host CA signing, installed certificates | Server and client certificates verify |
| 10–11 | Backend environment, management helper, database migrations | Django production checks pass |
| 12–14 | Key store, checkpoint, certificate policy, first custodian | Store exists; setup code delivered privately |
| 15 | Public HTTPS, API socket access, restricted custody gateway | nginx configuration passes |
| 16–17 | Start all services; custodian login, TOTP and manual unseal | Services active; organization key provisioned |
| 18–19 | End-to-end checks and operating commands | Test document can be uploaded and read |

There is one React frontend hosted separately. AWS serves the API and the small
custodian maintenance page bundled with the key service; no second React/Vercel
project is needed. One systemd target starts several processes on one EC2.

Commands with `REPLACE_WITH_...` need your actual value before execution. Source
archive hashes, AWS region, retention, operator CIDR and provider credentials
cannot be truthfully prefilled. Run blocks in order and stop on errors.

**Fresh installation:** follow every numbered section in order on the new host.
If a supposedly fresh path already contains data or keys, stop and investigate;
never delete a store or database to repeat initialization. Stop on command errors.

Executable source: `/var/www/securemail-backend/current`.
Python environment: `/var/www/securemail-backend/venv`.
Data and secrets stay under `/var/lib/onesmarter*` and `/etc/onesmarter*`.

Production startup is supported, but independent crypto review and live recovery
evidence remain pending. See PRODUCTION_STARTUP.md for the legacy checkpoint's
limitations. This guide is not a claim that AWS has been deployed or approved.

## 1. Create the EC2 host

In AWS, select the approved region and Ubuntu 24.04 LTS image. Choose adequate
RAM/disk for PostgreSQL, the application and native compilation; a tiny instance
is not capacity-certified. Use persistent storage and preserve required data
volumes on termination. Verify mounts before writing application/database data.

Allow inbound HTTPS 443, and SSH 22 only from your operator IP/network (or use
your existing Session Manager access). Do not expose 5432, 6379 or 8443.
Associate a stable public address and configure the API domain
`securemailbackend.onesmarter.com`. Confirm `custody.onesmarter.com` before creating
its record. The examples use frontend origin `https://securemail.onesmarter.com`.
Restrict the custody virtual host additionally by VPN/operator IP in nginx.

Provision the real audit archive, retention and least-privilege instance role.
Audit archival is separate from document storage and local evidence bundles.
Do not invent a bucket name to bypass startup validation. AWS-managed EBS encryption
uses KMS; resolve the OS/disk encryption policy if the no-KMS requirement includes
infrastructure. Application encryption does not encrypt every database/OS field.

From your computer:

```bash
ssh -i /path/to/your-ec2-key.pem ubuntu@REPLACE_WITH_EC2_PUBLIC_ADDRESS
```

All following Linux commands run on EC2 except the explicitly OFF-HOST CA step.

### 1.1. Prepare the audit bucket and EC2 role

In the AWS console, create a private S3 bucket in the approved region, enable
versioning and Object Lock, block public access, and select SSE-S3 encryption.
Record its exact name and region. Obtain approval for the retention period before
writing any COMPLIANCE-locked object: it cannot be shortened after the write.
See [AWS Object Lock setup](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html).

Attach an EC2 instance role scoped to this bucket's `batches/` prefix. The current
archive writer explicitly sets retention and then verifies the returned version:
its role needs object write, version read and retention permissions, including
`s3:PutObject`, `s3:PutObjectRetention`, `s3:GetObjectVersion` and
`s3:GetObjectRetention`. Do not grant delete or bucket-policy administration to
the application. Have the actual policy reviewed and test it against the deployed
adapter; this is separate from a proposed key-checkpoint receiver's identity.
[AWS retention permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html).

Use the instance role instead of putting long-lived AWS access keys in backend.env.
Set `AUDIT_BUCKET`, `AWS_REGION` and the approved `AUDIT_RETENTION_DAYS` in step 10.
An empty bucket setting will prevent Django startup. An unreachable or wrongly
permissioned bucket will prevent successful archival even if startup succeeds.

## 2. Install dependencies

On a fresh Ubuntu image:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config perl curl git ca-certificates xz-utils libffi-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev liblzma-dev libncurses-dev uuid-dev libpcre2-dev postgresql postgresql-client redis-server certbot
```

Ubuntu's default PostgreSQL version depends on the image. Discover the actual
cluster later. If your selected baseline is PostgreSQL 17, follow the
[official PostgreSQL Ubuntu repository setup](https://www.postgresql.org/download/linux/ubuntu/)
before installing postgresql-17. Do not accidentally create a second cluster.

## 3. Install the verified native PQ runtime

Install custom OpenSSL at `/var/www/onesmarter-openssl/bin/openssl`.
Do not replace Ubuntu's system OpenSSL/Python. Obtain approved
OpenSSL 3.5+ and Python 3.15+ source releases from their official sites. Verify
publisher signatures or independently obtained SHA-256 hashes before extraction.
Record the exact releases/hashes; do not assume the newest version is validated.

```bash
mkdir -p "$HOME/onesmarter-build"
cd "$HOME/onesmarter-build"
printf '%s  %s\n' REPLACE_WITH_VERIFIED_SHA256 REPLACE_WITH_ARCHIVE_FILENAME | sha256sum --check -
```

Repeat verification for each archive. Extract only after it passes. Set these to
your actual extracted directories, not the placeholder text:

```bash
OPENSSL_SOURCE="$HOME/onesmarter-build/REPLACE_WITH_OPENSSL_DIRECTORY"
PYTHON_SOURCE="$HOME/onesmarter-build/REPLACE_WITH_PYTHON_DIRECTORY"
NGINX_SOURCE="$HOME/onesmarter-build/REPLACE_WITH_NGINX_DIRECTORY"
```

Build OpenSSL into its private prefix:

```bash
cd "$OPENSSL_SOURCE"
./Configure --prefix=/var/www/onesmarter-openssl --openssldir=/var/www/onesmarter-openssl/ssl --libdir=lib shared
make -j2
make test
sudo make install_sw
```

For a fresh custom prefix, connect its default public trust store to Ubuntu's
maintained CA bundle. Check existing paths first; do not overwrite configured
trust stores on your current machine:

```bash
sudo install -d -m 0755 /var/www/onesmarter-openssl/ssl
sudo ln -s /etc/ssl/certs/ca-certificates.crt /var/www/onesmarter-openssl/ssl/cert.pem
```

This public trust bundle is used for outbound HTTPS/SMTP verification. It is
separate from the application's explicitly pinned private key-service CA.

Build Python against it:

```bash
cd "$PYTHON_SOURCE"
./configure --prefix=/var/www/onesmarter-runtime --with-openssl=/var/www/onesmarter-openssl --with-openssl-rpath=auto --with-ensurepip=install
make -j2
./python -m test test_ssl
sudo make install
```

Reduce build parallelism if memory is insufficient; do not disable validation.
The exact Linux build still needs verification on your image/architecture.

Nginx must independently use a PQ-capable OpenSSL. A fresh dedicated build can use:

```bash
cd "$NGINX_SOURCE"
./configure --prefix=/var/www/onesmarter-nginx --sbin-path=/var/www/onesmarter-nginx/sbin/nginx --conf-path=/etc/onesmarter-nginx/nginx.conf --pid-path=/run/onesmarter-nginx.pid --error-log-path=/var/log/onesmarter-nginx/error.log --http-log-path=/var/log/onesmarter-nginx/access.log --with-http_ssl_module --with-openssl="$OPENSSL_SOURCE"
make -j2
sudo make install
```

This creates a separate nginx binary. Do not run it alongside an existing shared
nginx on port 443. On your existing server, retain the verified ingress service
and select its actual service name in the target installer.

Sources: [Python releases](https://www.python.org/downloads/),
[nginx build options](https://nginx.org/en/docs/configure.html),
[OpenSSL source releases](https://openssl-library.org/source/).

## 4. Create accounts and directories

Skip existing accounts; the following creates only missing ones:

```bash
id onesmarter || sudo useradd --system --user-group --home-dir /var/lib/onesmarter --shell /usr/sbin/nologin onesmarter
sudo install -d -o root -g root -m 0755 /var/www/securemail-backend /var/www/securemail-backend/releases
sudo install -d -o root -g onesmarter -m 0750 /etc/onesmarter /etc/onesmarter/pki /var/lib/onesmarter
sudo install -d -o onesmarter -g onesmarter -m 0700 /var/lib/onesmarter/runtime
sudo install -d -o onesmarter -g onesmarter -m 0700 /etc/onesmarter-key /etc/onesmarter-key/pki /var/lib/onesmarter-key /var/lib/onesmarter-key/accounts /var/lib/onesmarter-key/backups
sudo install -d -o root -g root -m 0700 /etc/onesmarter-gateway /etc/onesmarter-gateway/pki /etc/onesmarter-rotation
```

The shared service user can read the executable source/runtime but must not modify it.
It can access both application and key-service data; separate paths are organizational,
not an OS-user security boundary. No unseal secret or CA signing key
belongs in these server directories.

## 5. Install source and the application venv

Use approved GitHub authentication; never embed a token in the clone URL:

```bash
checkout=$(mktemp -d /var/tmp/securemail-source.XXXXXX)
git clone --branch main --single-branch https://github.com/OneSmarterInc/securemail-backend.git "$checkout"
release_commit=$(git -C "$checkout" rev-parse HEAD)
printf '%s\n' "$release_commit"
```

Confirm the commit. Unified startup first shipped in f5feca4. For a NEW installation:

```bash
sudo mkdir "/var/www/securemail-backend/releases/$release_commit"
git -C "$checkout" archive "$release_commit" | sudo tar -x -C "/var/www/securemail-backend/releases/$release_commit"
sudo chmod 0755 "/var/www/securemail-backend/releases/$release_commit"
sudo ln -s "/var/www/securemail-backend/releases/$release_commit" /var/www/securemail-backend/current
sudo /var/www/onesmarter-runtime/bin/python3.15 -m venv /var/www/securemail-backend/venv
sudo /var/www/securemail-backend/venv/bin/python -m pip install --require-hashes --only-binary=:all: -r /var/www/securemail-backend/current/requirements.lock
```

Do not overwrite existing current/venv. Use ONE_COMMAND_AWS_STARTUP.md for the
existing-server release switch. Verify the actual application interpreter:

```bash
cd /var/www/securemail-backend/current
/var/www/securemail-backend/venv/bin/python -c 'import ssl; from backend.transport.tls import configure; print(ssl.OPENSSL_VERSION); configure(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), required=True); print("PQ configuration accepted")'
```

### 5.1. Create the fresh backend environment once

On a NEW installation only, create the environment from the repository template
and generate independent signing, integrity, search and database secrets directly
into its restricted file. Nothing secret is printed. If the file already exists,
this command refuses to overwrite it; keep your existing secrets.

```bash
sudo /var/www/securemail-backend/venv/bin/python - <<'PY'
import grp
import os
import secrets
from pathlib import Path
source = Path('/var/www/securemail-backend/current/deploy/aws.env.example')
destination = '/etc/onesmarter/backend.env'
values = {name: secrets.token_hex(32) for name in (
    'DJANGO_SECRET_KEY', 'DOCUMENT_INTEGRITY_KEY', 'SEARCH_INDEX_KEY', 'POSTGRES_PASSWORD'
)}
lines = []
for line in source.read_text().splitlines():
    name = line.partition('=')[0]
    lines.append(f'{name}={values[name]}' if name in values else line)
fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write('\n'.join(lines) + '\n')
    stream.flush()
    os.fsync(stream.fileno())
os.chown(destination, 0, grp.getgrnam('onesmarter').gr_gid)
os.chmod(destination, 0o640)
print('Created backend.env; complete the provider and archive settings privately.')
PY
sudoedit /etc/onesmarter/backend.env
```

Use the generated POSTGRES_PASSWORD privately at the database prompt below. Save
an encrypted off-host copy of the completed environment. It is not the unseal key.
The template is not runnable until the real archive and SMTP settings are filled.

## 6. Local PostgreSQL, Redis and name resolution

```bash
sudo systemctl enable --now postgresql redis-server
pg_lsclusters
sudo -u postgres psql -Atc "SHOW config_file;"
sudo -u postgres psql -Atc "SHOW hba_file;"
```

Edit the reported PostgreSQL config, preserving unrelated settings:

```conf
listen_addresses = '127.0.0.1'
password_encryption = 'scram-sha-256'
```

Preserve administrator peer access in pg_hba.conf and add this before broader
matching host rules:

```conf
host secure_mail secure_mail_app 127.0.0.1/32 scram-sha-256
```

Restart the actual cluster from pg_lsclusters; do not guess its version. Create
the application role/database only if absent:

```bash
sudo -u postgres createuser --pwprompt --no-superuser --no-createdb --no-createrole secure_mail_app
sudo -u postgres createdb --owner=secure_mail_app secure_mail
```

Enter the generated POSTGRES_PASSWORD from your private backend.env when prompted.
For an existing role, run `sudo -u postgres psql` and use `\password secure_mail_app`,
then `\q`; do not recreate the database.

Keep Redis on loopback with protected mode enabled; review its ACLs/persistence.

```bash
sudo ss -ltnp 'sport = :5432'
sudo ss -ltnp 'sport = :6379'
psql -h 127.0.0.1 -U secure_mail_app -d secure_mail -W -c 'SELECT current_database(), current_user;'
sudoedit /etc/hosts
```

Add/update one hosts entry without duplicates:

```text
127.0.0.1 keys.internal
```

```bash
getent ahostsv4 keys.internal
```

## 7. Private service keys and certificate requests

A fresh host needs workload, server, custody gateway and rotation identities. This block
skips existing pairs and refuses a partially existing pair:

```bash
sudo bash -eu <<'SH'
umask 077
openssl=/var/www/onesmarter-openssl/bin/openssl
make_request() {
  dir="$1"; name="$2"; cn="$3"; purpose="$4"; owner="$5"
  if [ -e "$dir/$name.key" ] || [ -e "$dir/$name.csr" ]; then
    if [ ! -f "$dir/$name.key" ] || [ ! -f "$dir/$name.csr" ]; then
      echo "STOP: incomplete existing $name key/CSR pair"
      exit 1
    fi
    echo "Preserving existing $name key and CSR"
    return
  fi
  extra=()
  if [ "$purpose" = serverAuth ]; then
    extra=(-addext 'subjectAltName=DNS:keys.internal')
  fi
  "$openssl" req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -sha256 -keyout "$dir/$name.key" -out "$dir/$name.csr" -subj "/O=OneSmarter/CN=$cn" -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature' -addext "extendedKeyUsage=$purpose" "${extra[@]}"
  chown "$owner" "$dir/$name.key" "$dir/$name.csr"
  chmod 0600 "$dir/$name.key" "$dir/$name.csr"
  "$openssl" req -in "$dir/$name.csr" -noout -verify -subject
}
make_request /etc/onesmarter/pki workload securemail-workload clientAuth onesmarter:onesmarter
make_request /etc/onesmarter-key/pki server keys.internal serverAuth onesmarter:onesmarter
make_request /etc/onesmarter-gateway/pki gateway custody-gateway clientAuth root:root
make_request /etc/onesmarter-rotation rotation offline-key-maintenance clientAuth root:root
SH
```

P-256 identity signatures are classical; hybrid TLS key exchange is separate.
The unencrypted runtime keys have restricted file ownership/mode. They are not
the document root key or unseal secret.

## 8. Sign certificates OFF-HOST

Prefer your approved private CA if one exists. Otherwise, use a separate trusted,
encrypted operator computer. These commands run in Linux/WSL ON THAT COMPUTER,
not EC2. Install a trusted OpenSSL distribution there first. Keep the CA key and
its encrypted backup off the application server. Establish renewal/revocation
operations; this small issuance example is not an independently reviewed PKI.

```bash
umask 077
mkdir onesmarter-private-ca
cd onesmarter-private-ca
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -aes-256-cbc -out ca.key
openssl req -new -x509 -sha384 -days 3650 -key ca.key -out key-service-ca.pem -subj '/O=OneSmarter/CN=OneSmarter Internal CA' -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' -addext 'keyUsage=critical,keyCertSign,cRLSign' -addext 'subjectKeyIdentifier=hash'
```

Choose a strong passphrase at the prompt. Do not run these commands over an
existing CA. Transfer ONLY workload.csr, server.csr, gateway.csr and rotation.csr
from EC2 to this directory via an approved SSH/file-transfer method. No .key files.

```bash
cat > client.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:keys.internal
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
```

Inspect each subject and verify its request before signing. Explicit extensions
prevent accidentally issuing CA privileges requested by an untrusted CSR:

```bash
for name in workload server gateway rotation; do
  openssl req -in "$name.csr" -noout -verify -subject || exit 1
  test ! -e "$name.pem" || exit 1
  extensions=client.ext
  [ "$name" != server ] || extensions=server.ext
  serial=$(openssl rand -hex 16)
  openssl x509 -req -in "$name.csr" -CA key-service-ca.pem -CAkey ca.key -set_serial "0x$serial" -days 90 -sha384 -extfile "$extensions" -out "$name.pem" || exit 1
done
openssl verify -CAfile key-service-ca.pem -purpose sslserver -verify_hostname keys.internal server.pem
openssl verify -CAfile key-service-ca.pem -purpose sslclient workload.pem gateway.pem rotation.pem
```

Transfer only the five public .pem certificates back to EC2, for example into
an operator-owned `$HOME/issued-certificates` directory. Never transfer ca.key.

## 9. Install certificates on EC2

```bash
sudo install -o root -g onesmarter -m 0640 "$HOME/issued-certificates/key-service-ca.pem" /etc/onesmarter/pki/key-service-ca.pem
sudo install -o onesmarter -g onesmarter -m 0640 "$HOME/issued-certificates/workload.pem" /etc/onesmarter/pki/workload.pem
sudo install -o onesmarter -g onesmarter -m 0600 "$HOME/issued-certificates/key-service-ca.pem" /etc/onesmarter-key/pki/ca.pem
sudo install -o onesmarter -g onesmarter -m 0600 "$HOME/issued-certificates/server.pem" /etc/onesmarter-key/pki/server.pem
sudo install -o root -g root -m 0600 "$HOME/issued-certificates/key-service-ca.pem" /etc/onesmarter-gateway/pki/ca.pem
sudo install -o root -g root -m 0600 "$HOME/issued-certificates/gateway.pem" /etc/onesmarter-gateway/pki/gateway.pem
sudo install -o root -g root -m 0600 "$HOME/issued-certificates/rotation.pem" /etc/onesmarter-rotation/rotation.pem
sudo install -o onesmarter -g onesmarter -m 0600 "$HOME/issued-certificates/workload.pem" /etc/onesmarter-key/pki/workload-client.pem
sudo install -o onesmarter -g onesmarter -m 0600 "$HOME/issued-certificates/gateway.pem" /etc/onesmarter-key/pki/gateway-client.pem
sudo install -o onesmarter -g onesmarter -m 0600 "$HOME/issued-certificates/rotation.pem" /etc/onesmarter-key/pki/rotation-client.pem
```

These are internal identity certificates, not browser-trusted public HTTPS certificates.

## 10. Environment and management launcher

Use your prepared backend.env; do not regenerate secrets on an existing install.

```bash
sudoedit /etc/onesmarter/backend.env
sudo chown root:onesmarter /etc/onesmarter/backend.env
sudo chmod 0640 /etc/onesmarter/backend.env
```

Verify POSTGRES_HOST=127.0.0.1 and its password, REDIS_URL, the real frontend/API
origins, and these certificate paths:

```dotenv
APP_ENV=production
DJANGO_READ_DOT_ENV=false
TRUSTED_PROXY_UNIX_SOCKET=true
KEY_PROTECTOR=key-service
KEY_SERVICE_URL=https://keys.internal:8443
KEY_SERVICE_CA=/etc/onesmarter/pki/key-service-ca.pem
KEY_SERVICE_CERT=/etc/onesmarter/pki/workload.pem
KEY_SERVICE_KEY=/etc/onesmarter/pki/workload.key
PQ_TRANSPORT_REQUIRED=true
MAIL_PROVIDER=smtp
EMAIL_HOST=smtp.ionos.com
EMAIL_PORT=587
```

Fill the real IONOS mailbox/password, authorized sender, AWS_REGION, AUDIT_BUCKET
and approved positive AUDIT_RETENTION_DAYS. Preserve application signing/integrity/
search keys. Keep SelfPay disabled until its adapter and separate mTLS identities
are deployed. Portal SMTP credentials also need setup; env alone does not replace them.

The complete starting template is `deploy/aws.env.example`, copied in step 5.1.
Check these values privately before proceeding:

| Variable | Required value |
|---|---|
| PUBLIC_URL | `https://securemail.onesmarter.com` |
| RECIPIENT_PUBLIC_URL | `https://securemail.onesmarter.com/recipient` |
| ALLOWED_HOSTS | `securemailbackend.onesmarter.com` |
| CSRF_TRUSTED_ORIGINS / CORS_ALLOWED_ORIGINS | `https://securemail.onesmarter.com` |
| APP_RUNTIME_DIR | `/var/lib/onesmarter/runtime` |
| POSTGRES_HOST / POSTGRES_PORT | `127.0.0.1` / `5432` |
| POSTGRES_DB / POSTGRES_USER | `secure_mail` / `secure_mail_app` |
| POSTGRES_PASSWORD | Same private value entered when creating the database role |
| EMAIL_HOST_USER / EMAIL_HOST_PASSWORD | Your actual IONOS mailbox and its password |
| DEFAULT_FROM_EMAIL | A sender that this mailbox is authorized to use |
| KEY_SERVICE_CUSTODIAN_DIRECTORY | `/var/lib/onesmarter-key/accounts` |
| DJANGO_SECRET_KEY / DOCUMENT_INTEGRITY_KEY / SEARCH_INDEX_KEY | Three different generated secrets from step 5.1 |

The backend enforces STARTTLS. Confirm your IONOS account's regional server details;
the `.com` service documents port 587 for STARTTLS.
[IONOS server settings](https://www.ionos.com/help/index.php?id=2490).
Do not use a Gmail or unrelated sender unless the provider explicitly authorizes it.

Install this root-owned loader; it reads dotenv without evaluating it as shell code:

```bash
sudo install -d -m 0755 /usr/local/lib
sudo tee /usr/local/lib/securemail-manage.py >/dev/null <<'PY'
import os
import sys
from dotenv import load_dotenv
if not load_dotenv('/etc/onesmarter/backend.env', override=True, interpolate=False):
    raise SystemExit('Backend environment is empty or unavailable')
os.environ['DJANGO_READ_DOT_ENV'] = 'false'
os.chdir('/var/www/securemail-backend/current')
os.execv(sys.executable, [sys.executable, 'manage.py', *sys.argv[1:]])
PY
sudo chmod 0644 /usr/local/lib/securemail-manage.py
sudo tee /usr/local/bin/securemail-manage >/dev/null <<'SH'
#!/bin/sh
exec sudo -u onesmarter /var/www/securemail-backend/venv/bin/python /usr/local/lib/securemail-manage.py "$@"
SH
sudo chmod 0755 /usr/local/bin/securemail-manage
```

Review/back up an existing launcher before replacing it. This version automatically
uses the service account; it fixes the earlier ubuntu-user read-permission issue.

## 11. Migrations and first administrator

Only after certificate files and real archive settings exist:

```bash
securemail-manage migrate --plan
securemail-manage migrate --noinput
securemail-manage check --deploy
securemail-manage bootstrap_admin --email REPLACE_WITH_COMPANY_EMAIL --name 'Workspace administrator'
securemail-manage key_status
```

Back up first on an existing database. Do not bootstrap a second first-admin.
Record the organization UUID printed by key_status. The service can still be
sealed during this metadata setup. Do not disable production validation on failure.

## 12. Initialize the key store and checkpoint

Generate the recovery/unseal secret on your SEPARATE trusted computer:

```bash
python3 -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode('ascii'))"
```

Retain it privately off-host. On EC2, initialize only a NEW store; the command
prompts twice without echo. Never delete a store to rerun initialization.

```bash
cd /var/www/securemail-backend/current
sudo -u onesmarter env APP_ENV=production /var/www/securemail-backend/venv/bin/python -m backend.keyservice init --store /var/lib/onesmarter-key/store.sqlite3
sudo -u onesmarter env APP_ENV=production /var/www/securemail-backend/venv/bin/python -m backend.keyservice checkpoint --store /var/lib/onesmarter-key/store.sqlite3 --destination /var/lib/onesmarter-key/initial-checkpoint.json
sudo install -d -o root -g onesmarter -m 0750 /etc/onesmarter-trust
sudo install -o root -g onesmarter -m 0640 /var/lib/onesmarter-key/initial-checkpoint.json /etc/onesmarter-trust/checkpoint.json
```

Independently retain the checkpoint and encrypted backup off-host. A local copy
alone does not protect against root compromise. Do not refresh an anchor blindly.

## 13. Register the certificate identities

Use the real organization UUID, not the staff ID. Run from the current checkout:

```bash
sudo -u onesmarter /var/www/securemail-backend/venv/bin/python -m backend.keyservice identity --policy /etc/onesmarter-key/policy.json --cert /etc/onesmarter-key/pki/gateway-client.pem --name custody-gateway --role custodian --days 30
sudo -u onesmarter /var/www/securemail-backend/venv/bin/python -m backend.keyservice identity --policy /etc/onesmarter-key/policy.json --cert /etc/onesmarter-key/pki/workload-client.pem --name application-workload --role workload --organization REPLACE_WITH_ORGANIZATION_UUID --days 30
sudo -u onesmarter /var/www/securemail-backend/venv/bin/python -m backend.keyservice identity --policy /etc/onesmarter-key/policy.json --cert /etc/onesmarter-key/pki/rotation-client.pem --name offline-key-maintenance --role maintenance --organization REPLACE_WITH_ORGANIZATION_UUID --days 30
```

Do not run concurrent policy writers. Certificate and policy expiry are independent;
schedule renewal before either expires. Do not use organization wildcards.

## 14. Create the first custodian and runtime environment

The Django custody CLI needs the management environment. Create the account under
the shared service user while the key service is stopped. This user can already
read the application environment under the selected single-user model:

```bash
sudo -u onesmarter /var/www/securemail-backend/venv/bin/python - <<'PY'
import os
import sys
from dotenv import load_dotenv
if not load_dotenv('/etc/onesmarter/backend.env', override=True, interpolate=False):
    raise SystemExit('Environment unavailable')
os.environ['DJANGO_READ_DOT_ENV'] = 'false'
os.environ['KEY_SERVICE_CUSTODIAN_DIRECTORY'] = '/var/lib/onesmarter-key/accounts'
os.chdir('/var/www/securemail-backend/current')
os.execv(sys.executable, [sys.executable, 'manage.py', 'custodian', 'create', '--username', 'ammar', '--name', 'Ammar Aziz', '--policy', '/etc/onesmarter-key/policy.json'])
PY
```

The command reports a private setup-file path. Deliver the temporary setup code
privately; it expires after 24 hours or completed setup. Do not paste it into chat.

```bash
sudoedit /etc/onesmarter-key/service.env
```

Contents (no application or unseal secrets):

```dotenv
APP_ENV=production
SYNTHETIC_MODE=false
KEY_SERVICE_CUSTODIAN_DIRECTORY=/var/lib/onesmarter-key/accounts
```

```bash
sudo chown onesmarter:onesmarter /etc/onesmarter-key/service.env
sudo chmod 0600 /etc/onesmarter-key/service.env
```

## 15. Public certificates and ingress configuration

Use your approved browser-trusted issuer. One issuance option is Certbot DNS
verification for a certificate covering both public hostnames:

```bash
sudo certbot certonly --manual --preferred-challenges dns -d securemailbackend.onesmarter.com -d custody.onesmarter.com
```

Follow its DNS TXT instructions. Manual DNS issuance does not provide automatic
renewal; establish reviewed renewal automation and nginx reloads. Use the actual
lineage paths reported, not a guessed filename.

The repository API example uses these paths; on a NEW setup you can link them
to the actual Certbot lineage (do not overwrite existing files):

```bash
sudo ln -s /etc/letsencrypt/live/securemailbackend.onesmarter.com/fullchain.pem /etc/onesmarter/pki/api-fullchain.pem
sudo ln -s /etc/letsencrypt/live/securemailbackend.onesmarter.com/privkey.pem /etc/onesmarter/pki/api.key
```

Install a reviewed nginx configuration for your actual host. The repository
provides an API example, not a fully provisioned custody site. Required inputs:
actual certificate paths, approved operator IPs and the verified nginx binary.
Do not overwrite an existing shared nginx configuration or introduce two port-443
listeners. Follow COMPLETE_DEPLOYMENT_GUIDE.md's Maintenance Gateway Linkage table.

The custody gateway must use its own client certificate, verify keys.internal,
require PQ upstream TLS, preserve Origin, rewrite cookie Path to /maintenance/,
allow only documented maintenance methods/routes, and restrict operator access.
Never publicly proxy wrap/unwrap/import or open port 8443 to bypass the gateway.

The API example now expects a separate SelfPay integration-client CA. Before that
integration is configured, use a reviewed copy that removes the three client-CA
directives and replaces the exact integration location with `return 403`.
Keep SelfPay disabled in the environment. Do not silently remove its mTLS check
while leaving the endpoint enabled. Restore the full template only after following
SELFPAY_INTEGRATION_SETUP.md and installing its separate client CA/certificates.

Validate using the actual ingress binary, e.g. for the dedicated build:

```bash
sudo /var/www/onesmarter-nginx/sbin/nginx -t
```

### Fresh dedicated host: register the custom nginx service

The following example is ONLY for a fresh dedicated ingress. On your existing
shared host, merge the sites into its reviewed configuration and use its existing
unit; do not replace it or bind a second process to 443.

Create `/etc/onesmarter-nginx/nginx.conf` with `sudoedit`. Substitute your real
operator/VPN CIDR for 203.0.113.10/32 (documentation-only address). The public
certificate referenced here must cover BOTH API and custody names.

```nginx
user www-data;
worker_processes auto;
pid /run/onesmarter-nginx.pid;
error_log /var/log/onesmarter-nginx/error.log warn;
events { worker_connections 1024; }
http {
    access_log off;
    server_tokens off;
    upstream custody_service { server 127.0.0.1:8443; }
    map "$request_method:$uri" $custody_allowed {
        default 0;
        "GET:/maintenance/" 1;
        "GET:/maintenance/portal.js" 1;
        "GET:/maintenance/portal.css" 1;
        "GET:/maintenance/custodian-qr.js" 1;
        "POST:/maintenance/login" 1;
        "POST:/maintenance/v1/custody-status" 1;
        "POST:/maintenance/v1/custody-audit" 1;
        "POST:/maintenance/v1/unseal" 1;
        "POST:/maintenance/v1/seal" 1;
        "POST:/maintenance/v1/rotate-root" 1;
        "POST:/maintenance/v1/logout" 1;
    }
    server {
        listen 443 ssl default_server;
        ssl_reject_handshake on;
    }
    # API site prepared from deploy/aws-api.nginx.conf.example as described above.
    include /etc/onesmarter-nginx/api.conf;
    server {
        listen 443 ssl;
        server_name custody.onesmarter.com;
        ssl_certificate /etc/onesmarter/pki/api-fullchain.pem;
        ssl_certificate_key /etc/onesmarter/pki/api.key;
        ssl_protocols TLSv1.3;
        ssl_ecdh_curve X25519MLKEM768;
        ssl_session_cache off;
        ssl_session_tickets off;
        ssl_early_data off;
        allow 203.0.113.10/32;
        deny all;
        client_max_body_size 128k;
        add_header Strict-Transport-Security "max-age=31536000" always;
        add_header Referrer-Policy no-referrer always;
        add_header X-Content-Type-Options nosniff always;
        if ($ssl_server_name != "custody.onesmarter.com") { return 421; }
        if ($args != "") { return 400; }
        if ($custody_allowed = 0) { return 404; }
        location /maintenance/ {
            rewrite ^/maintenance/(.*)$ /$1 break;
            proxy_pass https://custody_service;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host keys.internal;
            proxy_set_header Origin $http_origin;
            proxy_ssl_server_name on;
            proxy_ssl_name keys.internal;
            proxy_ssl_verify on;
            proxy_ssl_verify_depth 2;
            proxy_ssl_trusted_certificate /etc/onesmarter-gateway/pki/ca.pem;
            proxy_ssl_certificate /etc/onesmarter-gateway/pki/gateway.pem;
            proxy_ssl_certificate_key /etc/onesmarter-gateway/pki/gateway.key;
            proxy_ssl_protocols TLSv1.3;
            proxy_ssl_conf_command Groups X25519MLKEM768;
            proxy_ssl_session_reuse off;
            proxy_cookie_path / /maintenance/;
            proxy_cache off;
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_next_upstream off;
            proxy_connect_timeout 5s;
            proxy_read_timeout 60s;
        }
    }
}
```

Create the API copy and edit it as specified above (integration disabled):

```bash
sudo install -m 0644 /var/www/securemail-backend/current/deploy/aws-api.nginx.conf.example /etc/onesmarter-nginx/api.conf
sudoedit /etc/onesmarter-nginx/api.conf
```

The complete replacement for its exact integration location is:

```nginx
location = /api/integrations/threads { return 403; }
```

Also remove its three ssl_client_certificate / ssl_verify_client /
ssl_verify_depth directives until SelfPay is provisioned. Leave other API routes
and security settings unchanged. Unknown public hosts are rejected by the default
server above. Type the trailing slash in the custody URL.

Use a dedicated group for the API socket so nginx does not gain read access to
the application environment file. Create this API override before installing the
target; the installer preserves it:

```bash
getent group onesmarter-web || sudo groupadd --system onesmarter-web
sudo usermod -aG onesmarter-web www-data
sudo install -d -m 0755 /etc/systemd/system/onesmarter-api.service.d
sudo tee /etc/systemd/system/onesmarter-api.service.d/20-socket-group.conf >/dev/null <<'EOF'
[Service]
Group=onesmarter-web
SupplementaryGroups=onesmarter
EOF
```

On restart the API runtime directory/socket use this group; the API retains its
application-group access. Do not add www-data to onesmarter.
Verify the socket permissions and an actual proxied request after starting.

Create `/etc/systemd/system/onesmarter-nginx.service` with `sudoedit`:

```ini
[Unit]
Description=OneSmarter dedicated PQ HTTPS ingress
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/var/www/onesmarter-nginx

[Service]
Type=exec
ExecStartPre=/var/www/onesmarter-nginx/sbin/nginx -t
ExecStart=/var/www/onesmarter-nginx/sbin/nginx -g "daemon off;"
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGQUIT
Restart=on-failure
RestartSec=5
LimitCORE=0

[Install]
WantedBy=multi-user.target
```

Validate and load the unit without starting a competing listener:

```bash
sudo /var/www/onesmarter-nginx/sbin/nginx -t
sudo systemctl daemon-reload
sudo systemctl show onesmarter-nginx.service --property=LoadState
```

Use `--nginx-unit onesmarter-nginx.service` in the target installer for this fresh
dedicated setup. Use the existing unit name on a shared server. This configuration
example needs real TLS/access tests; writing it is not deployment evidence.

## 16. Install the target and start the stack

```bash
cd /var/www/securemail-backend/current
pg_lsclusters
systemctl list-unit-files 'postgresql*' 'redis*' '*nginx*'
```

Use your actual cluster and nginx unit names. Example:

```bash
sudo /var/www/securemail-backend/venv/bin/python scripts/install_systemd_stack.py --postgres-unit postgresql@17-main.service --redis-unit redis-server.service --nginx-unit onesmarter-nginx.service
sudo systemctl enable --now onesmarter.target
sudo systemctl status onesmarter.target onesmarter-keyservice onesmarter-api onesmarter-worker onesmarter-beat --no-pager
sudo ss -ltnp 'sport = :8443'
```

This starts the existing ingress/database/cache and four app processes. The key
service must bind only 127.0.0.1:8443 and starts SEALED. No automatic unseal occurs.
Workers can send eligible queued mail once readiness succeeds.

## 17. Unseal and provision the first organization key

Open https://custody.onesmarter.com/maintenance/ through the approved network.
Use the temporary setup code, choose a password and enroll TOTP. Enter the off-host
recovery secret on the page. Keep it out of service environments and scripts.

For a new organization, generate an operation UUID once and retain it. Then run
the following one-off root management process, using the separate rotation identity.
Replace the two identifiers first. Retry with the SAME operation UUID/reason:

```bash
sudo /var/www/securemail-backend/venv/bin/python - <<'PY'
import os
import sys
from dotenv import load_dotenv
if not load_dotenv('/etc/onesmarter/backend.env', override=True, interpolate=False):
    raise SystemExit('Environment unavailable')
os.environ['DJANGO_READ_DOT_ENV'] = 'false'
os.environ['KEY_SERVICE_CERT'] = '/etc/onesmarter-rotation/rotation.pem'
os.environ['KEY_SERVICE_KEY'] = '/etc/onesmarter-rotation/rotation.key'
os.chdir('/var/www/securemail-backend/current')
os.execv(sys.executable, [sys.executable, 'manage.py', 'rotate_wrapping_key', '--organization', 'REPLACE_WITH_ORGANIZATION_UUID', '--reason', 'Initial organization key provisioning', '--request-id', 'REPLACE_WITH_FIXED_OPERATION_UUID', '--expected-active', 'none'])
PY
```

Use `python3 -c 'import uuid; print(uuid.uuid4())'` once to obtain the operation ID.
Keep workload credentials in the ordinary API/worker environment. Rotation needs
a healthy backup/checkpoint setup; do not delete state to retry a failed operation.

## 18. Verify transport and application behavior

```bash
cd /var/www/securemail-backend/current
/var/www/securemail-backend/venv/bin/python scripts/verify_pq_endpoint.py --host securemailbackend.onesmarter.com --port 443 --ca /etc/ssl/certs/ca-certificates.crt
sudo -u onesmarter /var/www/securemail-backend/venv/bin/python scripts/verify_pq_endpoint.py --host keys.internal --port 8443 --ca /etc/onesmarter/pki/key-service-ca.pem --cert /etc/onesmarter/pki/workload.pem --key /etc/onesmarter/pki/workload.key
```

Verify staff/custodian MFA, saved portal IONOS credentials and authorized sender,
recipient OTP, upload/read/download, sealed rejection, restart and coordinated
off-host database/document/key restore. Check storage growth, archive lag, policy/
certificate expiry and alert ownership. Antivirus is intentionally not installed.
Localhost/SCRAM does not prove PQ database transport. Complete the release review
before accepting real confidential data.

## 19. Daily commands

```bash
sudo systemctl start onesmarter.target
sudo systemctl stop onesmarter.target
sudo systemctl restart onesmarter.target
sudo systemctl --failed
sudo journalctl -u onesmarter-keyservice -u onesmarter-api -u onesmarter-worker -u onesmarter-beat -n 100 --no-pager
```

Stop/restart affects the four Secure Mail processes. Shared PostgreSQL, Redis and
nginx remain running. Restart/reboot leaves keys sealed; a custodian must unseal
again. Never use systemctl isolate on this target.

For a fresh installation, complete every prerequisite before starting the target.
Store the private CA and recovery secret off-host and retain coordinated backups.

## 20. Troubleshooting in order

| Symptom | Check and correction |
|---|---|
| Backend environment is empty or unavailable | Use the step-10 launcher. Run `sudo -u onesmarter test -r /etc/onesmarter/backend.env`; do not make the file world-readable. |
| KEY_SERVICE_CA/CERT/KEY must name an existing file | Complete off-host signing and certificate installation; a CSR is not a certificate. |
| Audit archive bucket, region and positive retention are required | Fill the actual approved settings; do not disable validation. |
| keys.internal cannot resolve | Verify the step-6 hosts entry with `getent ahostsv4 keys.internal`. |
| TLS unknown CA / hostname mismatch | Verify the signed chain and server SAN `keys.internal`; do not turn off verification. |
| PQ runtime configuration fails | Inspect the venv's `ssl.OPENSSL_VERSION` and hybrid group support, not only the shell's `openssl version`. |
| API returns 502 | Check `onesmarter-api` logs, `/run/onesmarter/app.sock`, directory permissions and nginx's `onesmarter-web` membership. |
| Custody returns 403 | Check your operator IP/VPN allow rule before changing anything; do not open custody to everyone. |
| Document service disabled | Custodian must unseal; confirm organization key provisioning and service readiness. |
| Mail does not arrive | Check worker logs and delivery status, portal SMTP setup and authorized sender. Do not automatically retry uncertain deliveries. |

Keep log excerpts free of credentials. A successful `systemctl start` is not proof
of a working upload/email/recovery flow. Record the deployed commit, test results,
backup destination, restore evidence and renewal/alert owners before real-data use.
