# Switch an existing AWS install to one Secure Mail service user

All four application services run as `onesmarter`: API, key service, Celery worker
and scheduler. PostgreSQL, Redis and nginx keep their vendor service accounts.
The separate processes, mTLS checks and manual custodian unseal remain. Sharing a
UID removes the OS-user boundary between application and key-store files; a
compromised application identity has substantially more access. This is the
owner-requested deployment tradeoff, not equivalent isolation.

For a fresh installation, follow [AWS_FROM_SCRATCH.md](AWS_FROM_SCRATCH.md).
For your existing server, use this sequence. Stop on any failed command.

## 1. Preserve state and install the reviewed release

Back up the database, encrypted documents, key store, custodian account directory,
policy, configuration and certificates using your approved off-host procedure.
Preserve existing private keys and the off-host unseal secret. Do not initialize a
replacement store. Follow the release-switch steps in
[ONE_COMMAND_AWS_STARTUP.md](ONE_COMMAND_AWS_STARTUP.md) to put the new release at
`/var/www/securemail-backend/current` before installing its units.

## 2. Stop application processes

If the target already exists, stop it first:

```bash
sudo systemctl stop onesmarter.target
```

Then stop the four services directly, including any enabled independently:

```bash
sudo systemctl stop onesmarter-api onesmarter-worker onesmarter-beat onesmarter-keyservice
systemctl is-active onesmarter-api onesmarter-worker onesmarter-beat onesmarter-keyservice
```

Expect `inactive` for all four (the check returns nonzero for inactive services).
An unknown unit on a partially configured server means it was never installed;
confirm there are no manually launched application processes before continuing.
Do not stop shared PostgreSQL, Redis or nginx.

## 3. Transfer ownership of the existing key-service directories

The following uses fixed paths, refuses symlink roots and does not follow symlinks.
Review any mounted backup volume and its ownership policy before running it.

```bash
sudo bash -eu <<'SH'
id onesmarter
for path in /etc/onesmarter-key /var/lib/onesmarter-key; do
  test -d "$path"
  test ! -L "$path"
  readlink -f "$path"
done
chown -R --no-dereference onesmarter:onesmarter /etc/onesmarter-key /var/lib/onesmarter-key
chmod 0700 /etc/onesmarter-key /var/lib/onesmarter-key
if [ -f /etc/onesmarter-key/service.env ]; then
  chmod 0600 /etc/onesmarter-key/service.env
fi
if [ -f /etc/onesmarter-trust/checkpoint.json ]; then
  chown root:onesmarter /etc/onesmarter-trust /etc/onesmarter-trust/checkpoint.json
  chmod 0750 /etc/onesmarter-trust
  chmod 0640 /etc/onesmarter-trust/checkpoint.json
fi
SH
```

Keep the trusted checkpoint root-owned. Keep gateway and offline maintenance
private keys root-owned as well. The obsolete `onesmarter-key` Linux account can
remain unused; do not delete its home directory or the stored data.

## 4. Inspect overrides and install units

```bash
sudo systemctl cat onesmarter-api onesmarter-worker onesmarter-beat onesmarter-keyservice
pg_lsclusters
systemctl list-unit-files '*nginx*' 'redis*'
```

Remove stale `User=onesmarter-key` / `Group=onesmarter-key` overrides using
`sudoedit` on the specific override file shown. Preserve the API's dedicated
`onesmarter-web` socket group if configured. The installer rejects stale account
overrides and old `/opt/onesmarter` paths. Use the actual PostgreSQL cluster name
and nginx unit from the commands above; this example assumes PostgreSQL 17 and
the dedicated custom nginx build:

```bash
cd /var/www/securemail-backend/current
sudo /var/www/securemail-backend/venv/bin/python scripts/install_systemd_stack.py --postgres-unit postgresql@17-main.service --redis-unit redis-server.service --nginx-unit onesmarter-nginx.service
systemctl show onesmarter-api onesmarter-worker onesmarter-beat onesmarter-keyservice --property=Id,User,Group
```

Every `User` must be `onesmarter`. The API may use `Group=onesmarter-web` for
nginx socket access; this does not change its user. Do not change existing secrets.

## 5. Validate configuration, then start and unseal

```bash
securemail-manage check --deploy
securemail-manage migrate --plan
```

Apply any reviewed pending migrations after your database backup. Missing signed
certificates or archive settings must be completed using AWS_FROM_SCRATCH.md; the
account change does not remove those requirements.

```bash
sudo systemctl enable --now onesmarter.target
sudo systemctl status onesmarter-keyservice onesmarter-api onesmarter-worker onesmarter-beat --no-pager
```

Open `https://custody.onesmarter.com/maintenance/` through your permitted network.
Sign in with the custodian's password and TOTP, then supply the off-host unseal
secret. Restarting the key service seals it again. Never put the unseal secret in
an environment file or startup unit. Verify a sealed rejection and an authorized
document round trip with fictional data before considering live use.
