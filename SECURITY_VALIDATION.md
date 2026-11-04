# Security acceptance validation — 2026-11-04

## RP-03 follow-up: validate content fields before key access

`crypto.content_fields` requires a canonical base64 nonce of exactly 12 bytes using `protocol.decode(..., 12)`. Ciphertext must be a base64 string with at least 16 decoded bytes for the GCM authentication tag; noncanonical encodings are rejected. `decrypt` and `rewrap` validate these fields before `unwrap`. `decrypt_many` validates every envelope in a chunk before its `unwrap-batch` request and reuses the decoded fields. A bad later chunk cannot prevent requests already completed for earlier valid chunks; no malformed chunk is submitted to the key service.

Validation: **100 tests passed** across the new content-field regressions, existing crypto/known-answer tests, batch-decryption tests and RP-02 outbox regressions. `test_rp03_content_nonce_length_checked_before_unwrap` covers lengths 0, 8, 11, 13, 16 and 128 across decrypt, rewrap and batching, with assertions that neither unwrap nor key-service/key-selection functions run. Invalid encodings, non-string values, short tags and a malformed last batch item also fail before key access. Valid empty plaintext (16-byte tag-only ciphertext) still decrypts and rewraps without changing its nonce or ciphertext. Evidence: `.runtime/rp03-validation.xml`. Both Ruff checks pass. The earlier RP-06 GitHub run predates this local follow-up.

## RP-02 follow-up: isolate outbox failures

`mail.process_job` now checks custody readiness for every job, including jobs without a conversation. A previous positive batch result cannot authorize later work after sealing. Unverifiable/deformed payloads are marked `failed` with `payload_unverifiable` only when custody still reports ready; if custody becomes unavailable, the job remains retryable with a 15-second backoff and its encrypted payload retained. Credential/attachment decryption failures during sealing also retry, and readiness is checked again before opening SMTP.

The batch isolates unexpected exceptions per job, logs only a fixed event and the job identifier, and backs off jobs still queued/retry. It never blindly requeues `sending` jobs: existing stale-job recovery preserves ambiguous delivery outcomes as `uncertain`. Per-job and pre-SMTP readiness checks cost additional status operations; that is intentional to avoid trusting a stale batch-wide readiness result. A seal cannot undo an already in-flight SMTP submission.

Validation: **85 targeted tests passed**, including `test_rp02_poison_outbox_job_must_not_block_later_jobs` with tampered ciphertext, invalid JSON and non-object payloads, each followed by an actual queued OTP and notifications. Tests also cover sealed jobs with no conversation, resume after unseal, sealing between admission/decryption/SMTP open, mid-batch sealing, log redaction and preservation of possibly submitted jobs. Another **33 existing flow/shared-mail tests passed**. Evidence: `.runtime/rp02-verified.xml` and `.runtime/rp02-flows.xml`. Both Ruff checks passed. Tests use synthetic fixtures/captured SMTP; no real email was sent. The RP-06 CI run below predates RP-02 and is not evidence for this follow-up.

RP-06 follow-up: all eight GitHub Actions jobs passed together on commit `946ea0aae3cb60b22ff116420399cb8cbe84fc28`. See [CI_VALIDATION.md](CI_VALIDATION.md) for the exact run URL, retained logs and PostgreSQL/nginx/ClamAV/browser/security evidence. Earlier local-only infrastructure gaps below are historical; CI success still does not establish production deployment or independent approval.

## RP-01 follow-up: explicit application environment

Resolved: Django now raises `ImproperlyConfigured` for missing, empty or whitespace-only `APP_ENV` before selecting synthetic mode or loading local key/cookie defaults. An explicit value in the root `.env` is accepted when dotenv loading is enabled; process environment still takes precedence. No initializer silently assumes development: local initialization requires an explicit development/test selection, and container initialization requires explicit development. The example environment, Compose profile, CI browser environment and local startup instructions document or supply the selection. Existing production/PQ startup restrictions remain unchanged.

Validation: `test_rp01_missing_app_env_must_not_start_in_synthetic_mode` passes for all four missing/blank variants using fresh subprocesses with dotenv disabled. Explicit development/test startup, unsupported-environment rejection, initializer guards, environment loading and import-policy checks: **28 passed**. Django system checks, targeted lint/format and diff whitespace checks passed. The earlier full-suite results below predate this narrow follow-up; the full suite was not rerun for RP-01. Optional development-host restrictions are not introduced by this change.

Scope: current working tree, synthetic fixtures only. No real email, deployment, real-key rotation or production-data recovery is authorized by this validation. Existing production startup restrictions remain enforced. Passing implementation tests is not an independent cryptographic approval.

## Observed results

| Check | Result | Evidence |
| --- | --- | --- |
| Complete backend suite | 394 passed, 17 skipped, zero failures; 177.48 seconds | `.runtime/security-accepted-20261104.xml`; isolated SQLite profile |
| PQ key-service, checkpoint/recovery, load and custodian-browser suite | 42 passed, zero skipped | `.runtime/security-pq-final.xml`; Python 3.15 / OpenSSL 3.5.9; generated loopback certificates |
| Actual hybrid TLS adapter/downgrade checks | 8 passed | `scripts/check_pq_transport.py` output; scanner daemon is synthetic; deployed endpoints not tested |
| Browser journeys and included accessibility assertions | 39 passed | `.runtime/browser-check-xcsknr_r/`; isolated application, captured mail, local development custody |
| Focused checkpoint/retention regressions | 15 passed | `test_security_acceptance.py` and `test_snapshot_retention.py` |
| Recovery, checkpoint and snapshot suite | 35 passed | Includes `test_v2_remediation.py`; simulated restore failure still preserves old-root backups |
| Frontend build/format, Python lint/format, Django system check and migration drift | Passed | Local commands in runbook |

The PQ component load run used 50 concurrent opens, 50 staff opens and 500 recipient opens, making 650 batch calls: 18.503 seconds total, p95 7.734 seconds, zero errors. This is component evidence, not full-portal capacity or a production SLA. Earlier sandbox-denied/interrupted runs and the corrected restore-mock signature failure are not acceptance evidence.

Of the 17 full-suite skips, two (custodian browser and component load) passed in the separate PQ run. The remaining 15 require PostgreSQL/backup tooling (9), nginx (2), real ClamAV (3), or an explicitly authorized disposable AWS archive bucket (1). Those checks remain unverified here; Docker, psql, nginx and clamd were not available on this host's PATH. The repository CI definitions are not evidence that those jobs passed for this working tree.

Source baseline: `b6080ee581c7b17481a3cd50ff11182535f2b840` plus the current uncommitted working-tree changes. No publication or deployment was performed. Counts across suites overlap and must not be added as distinct test coverage.

## Repairs in this review

**SV-01 — High: internally consistent old key-store history could be accepted.** Confirmed by code inspection and regression execution. A complete older backup could satisfy the local audit-chain checks; those checks had no independently retained reference. The prerequisite is substitution of a valid historical backup/store. Consequences include recovery of stale key state and loss of evidence of subsequent events.

`backend/keyservice/store.py` now accepts an independently retained audit checkpoint. Unseal, fresh key operations and restore reject missing, malformed, conflicting or older checkpoint history and clear the loaded root. Restore does not publish its destination if validation fails. `checkpoint` exports the current verified audit position using exclusive creation and fsync. The `restore` and `verify-root-recovery` CLI commands require `--trusted-checkpoint`; synthetic `serve` supports the same option. Existing direct Python callers may omit it for compatibility; omission provides no external rollback protection.

This is an **audit-history anchor**, not a signed snapshot of all key/application state. It cannot detect loss after the checkpoint, selective state rollback with an intact audit chain, replacement of the checkpoint itself, or arbitrary host compromise. The checkpoint must be independently approved and protected outside the key host's write authority. Do not create a fresh checkpoint from a suspect backup and call it trusted. Full coordinated state recovery and external custody remain release gates.

**SV-02 — Regression coverage:** a pooled mTLS connection now performs an actual unwrap before sealing, verifies that fresh unwrap fails after seal acknowledgement, and verifies reads resume after unseal. Existing policy-revocation checks remain. Previously decrypted in-flight plaintext is not retroactively erased by sealing; no cross-request DEK cache is introduced.

**SV-03 — Medium: redundant backup reads during rotation.** Confirmed by execution and code inspection. Every rotation reopened all retained snapshot databases even when every snapshot was inside the unconditional seven-day preservation window. A 600-version history test exposed the accumulating I/O. The retention path now skips these reads only when no snapshot can expire. Once pruning is possible, the existing root-scoped retention calculation and deletion safeguards run unchanged. Regression tests prove recent snapshots remain untouched and expired snapshots still receive root checks. Audit verification and durable snapshot creation are unchanged; no private-key cache was added.

Formatting failures in the current working tree were corrected without changing security policy, assertions or thresholds.

## Validation matrix

| Area | Implementation / evidence | Remaining acceptance requirement | Owner |
| --- | --- | --- | --- |
| A: cryptography | Versioned authenticated hybrid wrappers; strict parsing, context binding, published primitive vectors and separate test-side primitive implementations in `test_crypto_vectors.py`; tamper/downgrade tests in `test_crypto.py` | Qualified external review of the exact construction, combiner, dependency provenance and migration. Test-side interoperability is not independent protocol approval. | Cryptographic reviewer |
| B: sealing | Service-mode local fallback rejection; cross-instance sealing; actual pooled mTLS unwrap rejection; SMTP/OTP credential fail-closed tests | Deployed identity boundaries, process/memory controls and operational seal propagation evidence | Security/platform |
| C: recovery | Atomic backups, root-recovery proof, concurrent rotations, old-document reads and external checkpoint regressions | Clean-machine coordinated restore of DB, objects, key store and configuration; off-host custody, quorum decision and approved RPO/RTO | Custodians/platform |
| D: transport | PQ-only adapter tests, actual loopback hybrid handshakes and downgrade rejection | Every deployed hop, certificates, ingress bypass tests and explicit email/authentication scope approval | Platform/security |
| E: app/storage | Authorization, BCC/private-message separation, revocation, encrypted SMTP credentials, scanning fail-closed and evidence-file publication tests | Live scanner/signature evidence, deployed buffering/log/storage/backup controls | App/platform |
| F: performance | Bounded pagination, batches, request-local reuse and pooled TLS; synthetic component load test | Representative end-to-end load on intended PostgreSQL/network/storage and capacity targets | Performance/platform |
| G: release/CI | Repository CI defines PostgreSQL, nginx, browser, PQ, ClamAV, dependency and secret checks | Successful CI for the exact reviewed revision and retained artifacts; external approvals remain mandatory | Release owner |

## Eight acceptance scenarios

| Scenario | Executable evidence | Evidence boundary |
| --- | --- | --- |
| Seal → deny fresh reads → unseal → recover | `test_custody_cutover_preserves_mfa_and_downloads_fail_closed`; `test_persistent_connection_checks_seal_and_revocation` | Local generated keys and service |
| Rotation and historical/concurrent reads | `test_crypto.py`, `test_keyservice.py` rotation/backup tests | Synthetic operations, not deployment availability |
| Wrong/missing recovery material | `test_security_acceptance.py`, existing root-loss tests | No output store published on failed recovery |
| Clean-machine restore | New-directory restore and unwrap in `test_old_valid_backup_is_rejected_by_external_anchor` | New directory on this host; actual clean-machine drill remains open |
| Tampering and rollback | `test_encryption_review.py`, `test_security_acceptance.py` | Audit-chain damage and whole-history rollback through trusted anchor; selective state rollback remains open |
| Certificate and downgrade rejection | `test_keyservice.py`, `test_pq_transport.py`, `scripts/check_pq_transport.py` | Real loopback TLS; deployed endpoints unverified |
| Revocation/BCC/private isolation | `test_shared_mail.py`, recipient and archive tests | Synthetic tenants, messages and attachments |
| SMTP custody while sealed | `test_real_key_store_seal_blocks_smtp_and_otp` | Real temporary key store; SMTP sending mocked; no real mail |

## Safe reproduction (PowerShell, repository root)

Use installed locked development dependencies (`requirements.lock`, `requirements-test.lock`). Test-only educational crypto libraries must never enter the runtime key-service image. Use a fresh evidence directory name for each run; retain JUnit files and the source revision/diff.

```powershell
$env:DJANGO_READ_DOT_ENV = 'false'
$env:APP_ENV = 'test'
$env:POSTGRES_HOST = ''
.venv\Scripts\python.exe -u -m pytest -q --basetemp=.runtime/security-new-run --tb=short --junitxml=.runtime/security-new-run.xml
.venv\Scripts\python.exe -m ruff check backend scripts
.venv\Scripts\python.exe -m ruff format --check backend scripts
.venv\Scripts\python.exe manage.py check
.venv\Scripts\python.exe manage.py makemigrations --check --dry-run
```

Do not run against inherited production environment variables. These commands disable dotenv loading; the pytest fixtures use temporary stores, synthetic scanning and captured mail. PostgreSQL concurrency requires the isolated PostgreSQL CI job rather than this SQLite run. A filesystem sandbox that denies atomic hard-link publication cannot validate evidence capture; run in a permitted disposable environment without weakening create-only publication.

With the supported Python/OpenSSL PQ runtime already provisioned:

```powershell
$env:RUN_PQ_TRANSPORT = '1'
$env:RUN_KEY_SERVICE_LOAD = '1'
.runtime\pq-python315\python.exe -u -m pytest backend/tests/test_keyservice.py backend/tests/test_security_acceptance.py backend/tests/test_pq_transport.py -q --basetemp=.runtime/security-pq-new-run --junitxml=.runtime/security-pq-new-run.xml
.runtime\pq-python315\python.exe scripts/check_pq_transport.py
Remove-Item Env:RUN_PQ_TRANSPORT, Env:RUN_KEY_SERVICE_LOAD
.venv\Scripts\python.exe scripts/check_browser.py
npm --prefix frontend run build
npm --prefix frontend run format:check
```

The browser runner creates isolated fixtures and stops its owned processes. PQ transport checks must fail on unsupported runtimes, not silently fall back. Explicitly skipped integration tests are not passes. Preserve `.runtime/key-service-load.json` and browser evidence separately from production artifacts. Never publish runtime keys, databases, sessions or credentials. After evidence retention, remove only verified run-specific synthetic directories; no application configuration rollback or real key rotation is needed.

## Release decisions and next actions

Synthetic testing is appropriate with these controls. A staging pilot must use synthetic data until the gates below are met. Real confidential data remains blocked.

1. Obtain qualified independent review of the exact cryptographic protocol and address its findings.
2. Establish independently protected checkpoint, recovery-secret and off-host backup custody; approve the remaining state-rollback threat model.
3. Perform a clean-machine coordinated restore and root-rotation/recovery drill with actual custodians and measurable RPO/RTO.
4. Verify every deployed transport path, scanner, PostgreSQL concurrency, nginx isolation and monitoring with retained evidence.
5. Run complete CI against the final reviewed revision, retain all results and have the release owner approve each remaining gate before changing production restrictions.
