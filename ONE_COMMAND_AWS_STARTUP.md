# AWS: one command to start Secure Mail

Updated 4 November 2026. Native Ubuntu/systemd, one EC2, no Docker.

After the one-time setup below, start everything with:

```bash
sudo systemctl start onesmarter.target
```

This starts the actual PostgreSQL cluster, Redis, nginx, Django API, key service,
Celery worker and one beat scheduler. The maintenance UI is served by the key
service through your configured custody nginx gateway, not a second frontend.
The target does not install missing software, issue certificates or unseal keys.

## 1. Know the paths

| Item | Path |
|---|---|
| Shared executable source | `/var/www/securemail-backend/current` |
| Shared Python environment | `/var/www/securemail-backend/venv` |
| Immutable release directories | `/var/www/securemail-backend/releases` |
| Application environment | `/etc/onesmarter/backend.env` |
| Application data | `/var/lib/onesmarter/runtime` |
| Key-service environment | `/etc/onesmarter-key/service.env` |
| Key-service data | `/var/lib/onesmarter-key` |
| Custodian accounts | `/var/lib/onesmarter-key/accounts` |
| Certificate policy | `/etc/onesmarter-key/policy.json` |
| Independently protected checkpoint | `/etc/onesmarter-trust/checkpoint.json` |

The API, key service, worker and beat all run as `ubuntu`. They retain
separate processes, environment files and data paths, but there is no OS-user
isolation between the API and key store. A compromise under this account can
access both. TLS policy and custodian unseal remain enforced by the service;
they do not compensate for shared-UID filesystem access. PostgreSQL, Redis and
nginx retain their own service accounts. Executable source/venv stay root-owned.
For an existing installation follow SINGLE_USER_DEPLOYMENT.md before startup.

## 2. Finish the prerequisites already identified on your server

You have created service accounts, data directories and two private keys/CSRs.
Those CSRs are not signed certificates. Before migrations/startup can succeed:

- Install the signed CA/workload/server certificates at the paths in the env/unit.
  Preserve the private keys you already created. Keep the CA signing key off-host.
- Provision a distinct custody gateway client certificate and allowlist its
  fingerprint/role in policy. Configure the restricted HTTPS maintenance gateway.
- Supply a real audit bucket, region and approved positive retention in backend.env.
  Do not use dummy values. This is separate from EC2 document storage.
- Configure localhost PostgreSQL and its application password; configure Redis.
- Initialize the key store ONCE, with the recovery secret retained off-host; export
  and independently retain the initial checkpoint. Never reinitialize an existing store.
- Create the named custodian account, policy identities and matching account directory.

Use AWS_ONLY_DEPLOYMENT_GUIDE.md for these preparation steps and
PRODUCTION_STARTUP.md for checkpoint details. This guide controls executable paths
and service lifecycle wherever older documents use `/opt/onesmarter` paths.
Do not place an unseal secret in any environment or systemd unit.

## 3. Deploy the new backend release

On EC2, use your existing authenticated Git deployment method to deploy the new
main commit. Do not edit the running release directory in place. For a fresh
release export, these commands use an operator-owned temporary checkout:

```bash
checkout=$(mktemp -d /var/tmp/securemail-release.XXXXXX)
git clone --branch main --single-branch https://github.com/OneSmarterInc/securemail-backend.git "$checkout"
release_commit=$(git -C "$checkout" rev-parse HEAD)
printf '%s\n' "$release_commit"
```

Verify the printed commit against the release you intend to deploy. If GitHub
requests authentication, use your approved credential method; do not put a token
in the URL. Stop here on any failure. Export into a NEW release directory:

```bash
sudo mkdir "/var/www/securemail-backend/releases/$release_commit"
git -C "$checkout" archive "$release_commit" | sudo tar -x -C "/var/www/securemail-backend/releases/$release_commit"
sudo chmod 0755 "/var/www/securemail-backend/releases/$release_commit"
readlink -f /var/www/securemail-backend/current
```

Record the old release path for rollback. Before switching an existing deployment,
back up application/key data and stop the four Secure Mail services during your
maintenance window:

```bash
sudo systemctl stop onesmarter-api.service onesmarter-worker.service onesmarter-beat.service onesmarter-keyservice.service
```

If a named unit has never been installed, systemctl may report it missing; verify
any existing Secure Mail processes are stopped before switching source. Do not
stop a shared nginx, Redis or PostgreSQL service.

Verify `current` is a symlink, not a real directory, before the following switch:

```bash
test -L /var/www/securemail-backend/current
```

If that succeeds and the source export succeeded, switch the link:

```bash
sudo ln -s "/var/www/securemail-backend/releases/$release_commit" /var/www/securemail-backend/current.next
sudo mv -T /var/www/securemail-backend/current.next /var/www/securemail-backend/current
```

Stop if current.next already exists rather than overwriting an unexplained file.
Install the release's locked dependencies into the existing verified PQ venv
during the same maintenance window if they changed:

```bash
sudo /var/www/securemail-backend/venv/bin/python -m pip install --require-hashes --only-binary=:all: -r /var/www/securemail-backend/current/requirements.lock
```

Neither service user should own or be able to write the venv/source. Both need
directory traversal and read/execute permission. Do not recursively change
permissions on private configuration/data to resolve executable access errors.

## 4. Identify the actual local service names

```bash
pg_lsclusters
systemctl list-unit-files 'postgresql*' 'redis*' '*nginx*'
```

For example, PostgreSQL version 17 and cluster main usually means
`postgresql@17-main.service`. Use YOUR output. `postgresql.service` is an umbrella
unit and does not prove that a particular database cluster started; the installer
requires an actual cluster unit. Redis/nginx defaults are redis-server.service
and nginx.service. If your custom PQ nginx has a different unit, select that unit.
Do not start two nginx instances competing for port 443.

## 5. Review existing overrides and install the stack

```bash
sudo systemctl cat onesmarter-api.service onesmarter-worker.service onesmarter-beat.service onesmarter-keyservice.service
```

Missing units are expected on a new installation. Existing low-memory drop-ins
may override ExecStart with old /opt paths: update them using deploy/low-memory
before installing. The installer refuses stale /opt/onesmarter overrides.

Run the installer, replacing the PostgreSQL example with your actual cluster:

```bash
cd /var/www/securemail-backend/current
sudo /var/www/securemail-backend/venv/bin/python scripts/install_systemd_stack.py --postgres-unit postgresql@17-main.service
```

If your installed service names differ, supply them explicitly:

```bash
sudo /var/www/securemail-backend/venv/bin/python scripts/install_systemd_stack.py --postgres-unit postgresql@17-main.service --redis-unit redis-server.service --nginx-unit nginx.service
```

The installer checks service existence and binaries, preserves replaced unit files
under `/var/backups/onesmarter-systemd`, installs the target/dependency drop-ins,
runs systemd-analyze verify and reloads systemd. It does NOT start anything, touch
environment values, migrate data, generate keys, or enable automatic unseal.
If verification fails, it restores the overwritten file contents.

## 6. Check environment, executable access and migrations

```bash
sudo -u ubuntu test -r /etc/onesmarter/backend.env
sudo -u ubuntu /var/www/securemail-backend/venv/bin/python --version
sudo -u ubuntu /var/www/securemail-backend/venv/bin/python --version
```

backend.env stays root:ubuntu mode 0640. service.env is readable only by the
key-service identity/operator and contains:

```dotenv
APP_ENV=production
SYNTHETIC_MODE=false
KEY_SERVICE_CUSTODIAN_DIRECTORY=/var/lib/onesmarter-key/accounts
```

Use your installed management launcher as the application account so it can read
the protected backend environment:

```bash
sudo -u ubuntu -- "$(command -v securemail-manage)" migrate --plan
```

Only after the plan succeeds and the database backup is ready:

```bash
sudo -u ubuntu -- "$(command -v securemail-manage)" migrate --noinput
sudo -u ubuntu -- "$(command -v securemail-manage)" check --deploy
```

If securemail-manage is missing or points to old paths, use the explicit dotenv
management launcher in AWS_ONLY_DEPLOYMENT_GUIDE.md, with this guide's paths.
If you see missing certificates or audit settings, finish step 2; do not switch
APP_ENV to development. Migrations are deliberately not performed on every boot.

## 7. Start everything with one command

After prerequisites, migrations and nginx configuration validation succeed:

```bash
sudo systemctl enable --now onesmarter.target
```

This also enables the stack on reboot. For later manual starts:

```bash
sudo systemctl start onesmarter.target
```

Worker startup can send eligible queued emails after key readiness; use your
authorized SMTP account. Redis/PostgreSQL dependencies start before API/jobs.
The target does not use a polling check that waits for unseal: otherwise the
maintenance UI could never become accessible to perform the unseal.

## 8. Check processes, then unseal through the custodian page

```bash
sudo systemctl status onesmarter.target onesmarter-keyservice onesmarter-api onesmarter-worker onesmarter-beat --no-pager
sudo ss -ltnp 'sport = :8443'
```

The key-service listener must be 127.0.0.1:8443 only. A target being active means
the startup transaction completed, not that every application function is healthy.
Type=exec verifies process execution, not TLS, database connectivity or unseal.
Check actual endpoint/readiness results and service logs as well.

1. Open `https://custody.onesmarter.com/maintenance/` through approved access.
2. Sign in with your named custodian account; complete password/TOTP setup if new.
3. Enter the off-host recovery/unseal secret on that page.
4. Provision the first organization key with the maintenance identity if this is
   a new store, following AWS_ONLY_DEPLOYMENT_GUIDE.md.
5. Verify the document service is ready and test a synthetic upload/read flow.

The API/jobs keep their existing fail-closed behavior while sealed. There is no
automatic unseal and no certificate-verification bypass in this change.

## 9. Stop, restart and troubleshoot

```bash
sudo systemctl stop onesmarter.target
sudo systemctl start onesmarter.target
```

Or restart the Secure Mail processes together:

```bash
sudo systemctl restart onesmarter.target
```

These propagate to the four Secure Mail processes via PartOf. Shared nginx,
PostgreSQL and Redis are started as dependencies but are NOT stopped/restarted
by this target; they may serve SelfPay or other applications. The key service
starts sealed after a restart and requires the custodian again. Do not run
`systemctl isolate onesmarter.target`.

For a failed start, inspect the failing unit:

```bash
sudo systemctl --failed
sudo journalctl -u onesmarter-keyservice -u onesmarter-api -u onesmarter-worker -u onesmarter-beat -n 100 --no-pager
```

Fix the reported prerequisite, then retry start. If start-rate limiting occurred,
reset the specific failed unit with systemctl reset-failed before retrying. Do not
reinitialize stores, rotate secrets or make environment files world-readable.

For predictable boot control, disable old direct boot enablement of the four
individual services (without --now); the enabled target will still start them:

```bash
sudo systemctl disable onesmarter-api.service onesmarter-worker.service onesmarter-beat.service onesmarter-keyservice.service
sudo systemctl enable onesmarter.target
```

Existing non-systemd workers or a second beat must be stopped through their own
supervisor; the target cannot discover them. Review unit backups before rollback.
Never roll back a key store/database just because a source release is rolled back.

Systemd semantics: [targets](https://www.freedesktop.org/software/systemd/man/latest/systemd.target.html)
and [unit dependencies / PartOf](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html).
This is service orchestration, not independent cryptographic approval or evidence
of a completed AWS deployment. Existing production security gates remain open.

## Verification for this update

- Windows/Python 3.12 backend regression suite: **586 passed, 19 skipped**.
- Ruff check, Ruff formatting check and migration-drift check passed.
- Local Ubuntu/systemd-analyze accepted the dependency graph with inert test
  services substituted for application executables. No services were started.
- The Linux-only graph test is also part of the backend pytest suite in CI.
- AWS installation, real service startup, custodian unseal and real email delivery
  have not been performed by this source update. Check the pushed commit's CI
  separately; local results are not production approval.
