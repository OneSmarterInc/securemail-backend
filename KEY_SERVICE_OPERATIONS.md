# Self-managed key service and custodian webpage

Local same-app preview: **http://localhost:5173/maintenance/**. The Vite gateway uses a dedicated PQ/mTLS client identity and preserves a separate custodian password login. See [LOCAL_MAINTENANCE.md](LOCAL_MAINTENANCE.md) for local credentials, restart instructions, and the shared-origin trust boundary. The standalone HTTPS route below remains available. Local HTTP is synthetic-only and does not satisfy the production browser transport requirement.

Updated 2026-10-28. Implemented synthetic candidate, not production approval. No AWS KMS or OSIVault dependency. The normal development application still defaults to its local synthetic protector; selecting the separate service requires the configuration and explicit migration below. Never switch an existing store without inventory and a verified backup.

## What the administrator does

1. An operator provisions a dedicated custodian certificate and account. An ordinary staff administrator does not automatically gain this permission. The same person can hold both roles through separate credentials.
2. Open the dedicated HTTPS maintenance origin with the provisioned browser client certificate. Enter the custodian username and password. Authentication works while document encryption is sealed.
3. The page shows **Sealed**. Retrieve the separately held recovery key, enter it and choose **Unseal key service**.
4. The service verifies audit-chain integrity and authenticates the encrypted root and existing private records before changing to **Ready**. Audit corruption clears live root references and exposes `audit_integrity=failed` through the status API. Incorrect material fails without replacing existing keys. The recovery field is cleared.
5. Authorized workloads can now wrap/unwrap document data keys. Signing out or the five-minute maintenance-session expiry does not seal the service. Choose **Seal key service** to stop new key operations. Already delivered plaintext and in-flight application operations cannot be recalled.
6. A process restart begins sealed and requires another operator unlock. Files remain encrypted and present on disk; they are not deleted by sealing, logout or a visitor session expiry.

The recovery key decrypts a root protection key, which decrypts persistent organization private material. The root remains in the key-service process memory while ready; private material and temporary keys are used in memory during operations. The recovery key is not intentionally saved in browser storage, request logs or the database. Browser/Python memory clearing is not guaranteed. Deployment must protect memory, dumps, swap, tracing and the custodian workstation. A privileged host compromise can extract or misuse live keys.

## Initialization and credentials

### Connection admission and network boundary

The key service accepts at most 16 concurrent connections and at most four per
immediate TCP source IP, counting both unauthenticated and authenticated connections.
IPv4-mapped IPv6 addresses share the IPv4 allowance. Excess connections are closed
before allocating a worker. TLS negotiation has a two-second total monotonic deadline
starting at admission, including worker scheduling; partial handshake bytes never
extend it. Completed TLS requests retain the separate ten-second socket timeout.
Timeouts, failed TLS and worker-start failures release admission capacity.

Keep port 8443 on loopback for same-host deployments (the CLI default), or bind it
only to a dedicated private interface for cross-host deployments. Firewall/security
group ingress must allow only the application workers and maintenance gateway;
do not publish this port to the Internet or use a public load balancer. Expose the
maintenance UI only through the controlled gateway. Never trust forwarded HTTP
headers for pre-TLS source accounting. NAT/proxies share a source allowance, so
size and test workload concurrency accordingly. Distributed sources can still fill
the total budget: application limits do not replace private-network isolation.
Actual production firewall/security-group enforcement requires deployment verification.

Run commands from the repository root using the installed runtime dependencies. Paths below are illustrative Linux deployment paths; provision their ownership and restrictive permissions first. The service is deliberately synthetic-only. Use one service process per SQLite store; multiple processes/replicas and automatic failover are unsupported.

Startup enforces exclusive service ownership using an OS-held `<store>.service.lock` file. Never delete that file to bypass a running owner; stop the owner first. Process termination releases the lock automatically. Use a local filesystem with working OS locks, not a shared network filesystem. A transactional seal epoch additionally invalidates other store objects before their next operation/status check. A failed seal transaction must be treated as an operational failure; already returned DEKs/plaintext cannot be recalled.

```bash
python -m backend.keyservice init --store /srv/onesmarter-keys/store.sqlite3
python -m backend.keyservice identity --policy /srv/onesmarter-keys/policy.json --cert /pki/custodian.pem --name custodian --role custodian
python -m backend.keyservice identity --policy /srv/onesmarter-keys/policy.json --cert /pki/workload.pem --name document-worker --role workload --organization ORGANIZATION_UUID
python -m backend.keyservice identity --policy /srv/onesmarter-keys/policy.json --cert /pki/maintenance.pem --name key-maintenance --role maintenance --organization ORGANIZATION_UUID
python -m backend.keyservice serve --store /srv/onesmarter-keys/store.sqlite3 --backup-directory /mounted-independent-backups/onesmarter --policy /srv/onesmarter-keys/policy.json --cert /pki/server.pem --key /pki/server.key --ca /pki/client-ca.pem --origin https://keys.example.test:8443 --host 127.0.0.1 --port 8443 --synthetic-only
```

Replace the organization placeholder with its actual UUID. Certificates must be issued through an approved PKI: server SAN must match the HTTPS hostname, server/client EKUs must be appropriate, and clients require a trusted issuing CA. The custodian browser needs its own certificate/private-key credential provisioned through the operating system/browser certificate facility. The application gets a different workload certificate. This runbook does not provision a public hostname, trusted PKI or install browser credentials. Bind/network exposure must match the deployment design; do not bypass mTLS at a reverse proxy.

Initialization generates a random recovery secret and writes it without printing it; move it into separately controlled custody and verify recovery before deleting any staging copy. Windows requires explicit ACL management; POSIX chmod is not a substitute. Never put recovery material in `.env`, command-line arguments, container images, source control or application secrets configuration. Custodian registration prompts for a password and stores only its Argon2 hash. Certificates are allowlisted by SHA-256 fingerprint with expiry and exact organization scopes. Policy changes are reread on each request; changes invalidate existing maintenance sessions. Protect and back up policy and PKI separately. Do not perform concurrent policy-file writes.

## Application integration and existing records

Nonsecret settings: `KEY_PROTECTOR=key-service`, `KEY_SERVICE_URL`, `KEY_SERVICE_CA`, `KEY_SERVICE_CERT`, `KEY_SERVICE_KEY`. The last three are filesystem paths; protect private-key files. No recovery/root secret belongs in these settings. The HTTPS client requires TLS 1.3, validates server certificates, uses client authentication, has bounded responses/timeouts and never falls back to local protection after service failure.

For the strict transport profile also set `PQ_TRANSPORT_REQUIRED=true` and use Python 3.15+ with hybrid-capable OpenSSL. The client requires and checks `X25519MLKEM768` before sending key material. The `serve` CLI now defaults to PQ-only transport, including custodian browser connections. Existing classical synthetic previews must explicitly pass `--allow-classical-synthetic`; never use that flag in the strict profile. See [PQ_TRANSPORT.md](PQ_TRANSPORT.md) for runtime, scanner, edge and recovery requirements.

Private-key import is disabled by default, even for a maintenance certificate whose existing policy lists `import`. Both dispatch and the store require the key-service process environment to explicitly contain `APP_ENV=development` or `test`, `SYNTHETIC_MODE=true`, and `KEY_SERVICE_ALLOW_SYNTHETIC_IMPORT=true`. These are operator settings, never request parameters. New maintenance identities omit `import` unless registration runs with the same synthetic opt-in; an enabled synthetic service still requires the maintenance role, explicit import permission and matching organization scope. The `--synthetic-only` startup flag alone does not authorize import. Production/staging imports are denied; a reviewed custodian dual-control production import workflow is not implemented.

Only for isolated synthetic migration, enable those settings and a narrowly scoped maintenance certificate, then run `python manage.py import_local_keys --organization ORGANIZATION_UUID` for validation followed by `--apply`. Imports remain idempotent and decrypt-only; originals are preserved. Remove import permission and disable the opt-in after migration, restart the service and unseal normally. Use `rotate_wrapping_key` with maintenance credentials to create an active service version, then configure workload credentials for the application. Verify retained documents before retiring the local protector and preserve old backups with matching keys. Never send private import material through the browser. This gate does not remove previously imported keys or repair historical exposure; review existing key provenance separately before production use.

Before that import, any v1 envelopes must be converted in an isolated offline maintenance run with the application stopped, `KEY_PROTECTOR=local-development` and `ALLOW_LEGACY_SYNTHETIC_READS=true`. Run `python manage.py rewrap_keys --organization ORGANIZATION_UUID` to inspect candidates, then add `--apply` and repeat until no candidates remain and all skipped counters have been reconciled. Per-record crypto failures are reported and skipped without replacing the original; this does not mean those records migrated successfully. This converts eligible v1 to local v2; import those v2 private versions next using the steps above. Service mode rejects v1 even when the legacy flag is true. Do not temporarily re-enable a local protector in a serving application to bypass a sealed service, and do not delete keys required by old backups.

The Django mirror stores public metadata and service references, not service private keys. Runtime unwrap returns a temporary document DEK to the authorized application, which decrypts the requested content. Compromising that application can misuse its scoped unwrap authority. The service cannot independently establish end-user permission; Django must enforce document ownership/access on every operation. Service-native rewrap keeps the DEK inside the service. The existing application migration path also reads the DEK to authenticate content before replacing its wrapper.

## Internal HTTP contract

Every request uses mTLS. JSON POST requests have exact fields and a 16 KiB limit. There is no root/private-key export endpoint. Operations enforce both policy allowlists and role constraints. Workload requests do not use browser session cookies.

| Route | Fields | Authority/result |
| --- | --- | --- |
| `/login` | username, password | Custodian certificate, exact Origin; HttpOnly/Secure/SameSite session and CSRF token |
| `/v1/custody-status` | none | Custodian session/CSRF/Origin; sealed state and root identifier |
| `/v1/unseal` | secret | Custodian session; canonical Base64 random 32-byte secret |
| `/v1/seal` | none | Custodian session; clears live root references |
| `/v1/rotate-root` | secret, expected | Custodian session; new recovery secret and expected root UUID |
| `/v1/logout` | none | Custodian session; revoke login, keep sealing state |
| `/v1/status` | none | Authorized service identity; safe status/checkpoint |
| `/v1/versions` | organization; optional active (boolean), after (canonical UUID) | Scoped public metadata, at most 100 entries; returns versions and next_cursor. active=true returns only the active key and cannot be combined with a nonempty cursor |
| `/v1/rotate` | organization, expected, request_id | Maintenance; active-version compare-and-swap, UUID idempotency key |
| `/v1/import` | organization, key_id, private | Disabled by default; explicitly enabled synthetic environment plus scoped maintenance permission only; never export |
| `/v1/wrap` | organization, context, dek, expected | Workload; exact active version and context-bound wrapper |
| `/v1/unwrap` | organization, context, wrapper | Workload; temporary Base64 DEK |
| `/v1/rewrap` | organization, context, wrapper, expected | Workload; new wrapper, same DEK |

Django uses `active=true` so active-key resolution is independent of retained history. Historical clients must follow `next_cursor` using `after` until it is null; an exactly full last page may require one final empty request. Existing requests without optional fields return the first page. Deploy the service update before the Django update: old servers reject the new field rather than silently falling back. Cursor pagination is not a snapshot during concurrent rotation.

Audit verification detects inconsistent hashes, links and sequence gaps at unseal. It cannot detect a fully rewritten chain or rollback to a valid older store without an independently protected checkpoint. Preserve external checkpoint/restore controls as release gates; do not repair a failed audit by rewriting history. Investigate and recover from verified backups. `verified_at_unseal` means verification at that point, not continuous integrity attestation.

400 rejects malformed/unsupported material, 403 denies identity/scope/session/rate-limit failures, 409 indicates a state conflict, and 503 indicates sealed/unavailable service. Root mutations are limited to five attempts per minute per certificate; login has its own five-per-minute limit. TLS connections and request execution are bounded. TLS 1.3 alone does not establish post-quantum transport: actual negotiated algorithms on every required path remain a release gate.

## Rotation and recovery

Admission now separates workload (6000/min), batch (3000/min, at most 25 envelopes per call), and custodian (600/min) budgets. Both per-certificate and category-wide limits are preflighted before charging either. The operator policy may lower an identity's limits with `rate_limits` keys `workload`, `bulk`, and `custody`. Revoked/unlisted peers consume none of these budgets. Root operations retain their additional 5/min cap. Custodians also have eight reserved authenticated connection slots, separate from 64 workload slots; denied peers have four response slots. The pre-TLS limits remain 16 total/four per IP with a two-second deadline. These are capacity guards, not proof of production throughput. Restart the key service to load policy code, then unseal through the normal custody procedure.

Organization-version rotation retains old versions as decrypt-only; old documents remain readable. Rewrapping changes the DEK wrapper and preserves content ciphertext. Root rotation generates a new root, re-protects all private versions and updates the encrypted root header in one transaction, then changes memory state. Interrupted transactions roll back. It serializes operations and requires sizing/latency tests before production. The new recovery input must be generated using a cryptographically secure generator, not a password; length validation cannot establish entropy.

Before root rotation, take a verified encrypted backup with `python -m backend.keyservice backup --store STORE_PATH --destination NEW_BACKUP_PATH`. Keep the matching old recovery material separately. Save the new recovery material separately before submitting the rotation form. An old backup still needs the old secret. If the response is lost, inspect the root identifier and perform an isolated restore/unseal check; do not blindly repeat rotation or destroy either secret.

Restore a copied encrypted backup into an isolated service, use its matching recovery secret, verify key inventory and representative retained documents, and validate application/object metadata consistency before cutover. SQLite backup covers the key store only: object versions, PostgreSQL, policy, certificates, formats/dependencies and custody material need coordinated recovery planning. Losing every usable key/recovery copy makes retained ciphertext unreadable.

After root rotation, `recovery_verification_required` remains true across restarts. Old-root snapshots remain available, ordinary retention pruning pauses, and another root rotation is refused. Merely unsealing does not clear this gate. Stop the key service, retrieve the **new secret from its saved custody location**, and run this offline drill (the secret is prompted securely, never supplied as an argument):

```sh
python -m backend.keyservice verify-root-recovery --store STORE_PATH --backup-directory BACKUP_DIR --expected-root NEW_ROOT_UUID --destination NEW_ISOLATED_RESTORE_PATH --trusted-checkpoint INDEPENDENT_CHECKPOINT_PATH
```

The command requires exclusive store ownership. Its local drill unseals the live store with the new secret, creates an encrypted recovery-proof backup, and restores it to a new destination, checking integrity, audit history and every private key. **Local success does not authorize old-root deletion.** Retirement additionally requires `--off-host-backup` and `--recovery-evidence`, verified against separately provisioned public identities in `KEY_SERVICE_RECOVERY_TRUST`. The signed remote-copy receipt and clean-machine restore evidence must name the same root and exact downloaded digest, approved independent hosts, a valid time window and representative document checks. The restored private versions must match the live store. Missing/invalid proof leaves old-root snapshots and the pending recovery marker intact. See REVIEW_HANDOFF_2026-11-04.md. Unreconciled `.pending` files are never retired by this command. Restart the service and unseal normally afterward.

Protect the recovery-proof backup and isolated restored store as key material. They and external copies need an explicit custody/retention inventory; they are not automatically pruned. Reconcile pending snapshots against committed history before retiring them. Keeping old-root copies until recovery is proven deliberately extends exposure to a compromised old secret; complete the drill promptly. File deletion does not prove physical erasure or removal of off-host/filesystem copies. A key-store drill does not replace a coordinated document/application restore test.

## Evidence and remaining release gates

`backend/tests/test_keyservice.py` tests real local HTTPS/mTLS, role/scope rejection, wrong secrets, sealed restart, concurrent reads/rotation, idempotency, rollback, encrypted backup restoration and Django migration without persistent private-key export. `test_crypto_vectors.py` uses a pinned public ML-KEM KAT, RFC X25519/HKDF vectors and AES-GCM known answers, plus two-direction comparison with separate primitive implementations. Test-only kyber-py must never enter runtime code. These tests do not constitute independent protocol review.

The optional browser check uses headless Edge and temporary synthetic certificates: install frontend dependencies, set `RUN_KEY_PORTAL_BROWSER=1`, and run `pytest backend/tests/test_keyservice.py::test_custodian_browser`. It verifies login/unseal/cleared input/seal/logout and creates `.runtime/key-custody.png`. Its certificate-validation bypass is confined to the synthetic browser test.

The local audit chain and SQL triggers are tamper-evident relative to a retained trusted checkpoint, not immutable against host/database owners. External anchoring, audit verification/export, storage-failure alerting and production retention remain outstanding. Also required: independent exact-profile/dependency review, verified PQ transport, production PKI/custodian approval, OS memory hardening, PostgreSQL/deployment fault drills, capacity/availability validation and approved region/retention policy. No production gate is removed by this implementation.

## Rotation backup and off-host custody update (29 October 2026)

Initialization now prompts for a random 32-byte base64 secret generated and kept
in separate off-host custody. It does not write that secret to the key host.
A filesystem path outside the store directory is not proof of separate-host custody.
The old recovery-file mode and localhost bootstrap script require the explicit
`--allow-local-recovery-synthetic` option; never use that exception for real data.
Existing local demo custody artifacts have not been moved or deleted by this change.

Serve requires `--backup-directory`. Provision a separately protected off-host
mounted destination and exercise actual outage/recovery before deployment. Local
synthetic tests use a same-host directory and do not prove disaster durability.
Before activating a rotated/imported key or committing root rotation, the store
creates and fsyncs a complete encrypted-key snapshot from the pending transaction.
Backup failure aborts activation. A crash after snapshot but before commit can
leave an extra unused snapshot; reconcile with the protected audit checkpoint,
not just filename timestamps. Before creating a checkpoint, verify the complete
source audit chain; verify the copied chain and SQLite integrity before publication.
A corrupt source seals the store and aborts the pending mutation without replacing
existing backups. A copied-snapshot verification failure aborts publication.

For committed managed snapshots under the current root, retain every snapshot for
seven days, then the earliest available snapshot per UTC day through day 30. Always
retain at least the newest three, even if older than 30 days. Age is calculated from
the generated nanosecond filename timestamp; future timestamps are preserved after
clock rollback. This is a candidate operational policy, not an approved production
retention requirement. Pruning runs only after a new verified snapshot commits.
It pauses while root recovery verification is pending and never automatically removes
other-root snapshots, `.pending` files, manual backups or recovery-proof artifacts.
Old-root retirement remains a separate explicit verified-recovery operation.

Monitor backup capacity: frequent MFA writes produce full snapshots, and seven days
of complete history can use substantial storage. Disk exhaustion must reject key
mutations rather than silently shortening retention. Full audit verification and
snapshot creation hold the store lock; measure latency and disk growth before release.
Local chain checks cannot detect an attacker coherently rewriting/truncating history;
independently anchored checkpoints and protected off-host backups remain required.

Restore to a new path only:

```sh
python -m backend.keyservice restore --backup /backup/snapshot.sqlite3 --destination /recovery/new-store.sqlite3 --trusted-checkpoint /custody/approved-checkpoint.json
```

The CLI prompts for the matching off-host secret, checks SQLite integrity, audit
consistency and every encrypted private record, then publishes a sealed store.
It refuses an existing destination. Root-rotation backups need the corresponding
new secret; retain old custody for retained older backups. A successful local
restore is not proof that the backup mount is off-host or that the snapshot is
fresh. External checkpoints and coordinated application/key restoration remain gates.

Custody roadmap: select an independently reviewed threshold-sharing or HSM-backed
root-unseal design; require M-of-N separate custodians/devices, scoped identities,
quorum approval/audit, lost-share and compromise recovery, and drills before real
PHI use. Do not implement ad-hoc Shamir mathematics or claim that a single secret
and password constitute a quorum. Budget, exact threshold, hardware/provider and
operator approval remain unresolved.


## P3 hardening update

See [P3_REMEDIATION.md](P3_REMEDIATION.md) for stable rotation IDs/expected versions, recipient URL cleanup, bounded encrypted-subject search, and deployment verification limits. Rotation retries must reuse the original operation parameters.

## Independently retained audit checkpoints (2026-11-04)

Stop the service for exclusive offline access. From a known-good store, export a new checkpoint and then take its matching backup:

```text
python -m backend.keyservice checkpoint --store STORE_PATH --destination NEW_CHECKPOINT_PATH
python -m backend.keyservice backup --store STORE_PATH --destination NEW_BACKUP_PATH
```

The checkpoint contains an audit sequence and SHA-256 digest, not private keys. Independently approve and retain it off-host, outside the key-service writer's control. Supply a read-only trusted copy with `serve --trusted-checkpoint PATH`; restore and root-recovery verification require that option. A configured missing, invalid or conflicting checkpoint clears the loaded root and denies fresh key operations. Fixing the file alone does not unseal it.

Deliberately advance the retained checkpoint only after validating the new state and backup. Never derive trust from a suspect restored store. This anchor detects whole audit-history rollback through its retained position. It does not attest every database row, prevent selective state rollback with preserved audit history, detect loss after its position, or resist an attacker who can replace the checkpoint too. Omitting the optional synthetic serve setting provides no external rollback protection. See [SECURITY_VALIDATION.md](SECURITY_VALIDATION.md) for remaining custody and deployment gates.
