# Current evidence boundary — 2026-11-04

See D1_D6_VALIDATION.md for current candidate checks. Current-revision CI is
**pending**; historical green runs in CI_VALIDATION.md apply only to their exact
commits. They do not cover this uncommitted candidate change.

Local candidate validation: collected backend suite **548 passed / 18 skipped**;
selected actual hybrid-runtime suite **62 passed**; root routing/dependency tests
**13 passed**. Unrelated portal files changed concurrently: these counts do not
certify subsequent edits or replace a frozen-commit CI run.

The supplied review baseline was 370 passed / 17 skipped on SQLite and
380 passed / 9 skipped / 5 xfailed on PostgreSQL 16. These are historical,
user-supplied counts, not results re-observed here. The sections below preserve
earlier verification history and commands; their counts are not current totals.

# Historical local verification

Updated 2026-10-28. Tests use fictional accounts and files. Never point these tests at a live workspace.

## Backend

Run `python -m pytest -q` with the repository virtual environment after `scripts/init_local.py`. The suite covers routing, explicit Nophi authorization, staff MFA and activation, OTP attempts/one-time use, idempotency, scoped document upload/download, revocation, account lifecycle, last privileged administrator protection, audit mutation rejection, snapshots, export escaping, file rejection, actual hybrid encryption, rewrapping and recovery.

Native tests use SQLite with `IMMEDIATE` transactions to serialize local writes predictably. PostgreSQL remains the target database. `.github/workflows/checks.yml` defines PostgreSQL-backed tests; they have not been executed remotely in this session. SQLite passing does not establish PostgreSQL race behavior.

Run `python manage.py check`, `python manage.py makemigrations --check --dry-run`, `python -m ruff check backend scripts`, and `python -m ruff format --check backend scripts` as well.

## Frontend

In `frontend/`, use `npm ci`, `npm run build`, and `npm run format:check`. The build includes strict TypeScript checking. No frontend runtime tokens or decrypted content are stored in localStorage.

## Browser flow in an isolated workspace

Use three terminals, with the virtual environment installed. First, from the repository root:

```powershell
$env:APP_RUNTIME_DIR = Join-Path (Get-Location).Path '.runtime\browser-test'
$env:PUBLIC_URL = 'http://127.0.0.1:5174'
$env:CSRF_TRUSTED_ORIGINS = 'http://127.0.0.1:5174'
.\.venv\Scripts\python.exe scripts/init_local.py
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8001 --noreload
```

Second, from the repository root:

```powershell
$env:APP_RUNTIME_DIR = Join-Path (Get-Location).Path '.runtime\browser-test'
.\.venv\Scripts\python.exe manage.py runworker
```

Third, from `frontend/`:

```powershell
$env:API_TARGET = 'http://127.0.0.1:8001'
npm run dev -- --port 5174
```

Then run `npm run test:e2e` in `frontend/`. The default browser is installed Microsoft Edge. On Linux, set `E2E_BROWSER=chromium` and install the matching browser with `npx playwright install --with-deps chromium`. All test processes must be in the same network environment; Windows sandboxed processes may not be reachable by an unsandboxed Edge browser.

The test creates its own administrator and authenticator, then performs a real browser/API/database/outbox flow: staff request → recipient invitation → mailbox code → upload and reply → staff read and byte-for-byte file download. It also checks account creation, account search/sorting, audit search/details, absence of audit mutation actions, mobile reflow and uncaught browser errors.

`.runtime/browser-artifacts/` holds screenshots, a synthetic password/authenticator fixture and saved test session state. It is ignored by Git. Recipient browser contexts explicitly start with empty storage so they never inherit staff cookies. Repeated runs reuse the synthetic staff account and create uniquely named fictional recipients/staff. If starting from scratch, use a new dedicated runtime and matching artifact directory; do not delete a shared workspace or its root key.

## Evidence limits

Legacy KMS mocks were replaced with unsupported-provider rejection and actual self-managed HTTPS/service recovery tests. Local mail capture is not Proton delivery; a marker-based synthetic scanner is not antivirus. S3 archive enforcement still needs live verification. See [RELEASE_GATES.md](RELEASE_GATES.md).

## Required self-managed encryption evidence — not yet passed

- Primitive known-answer vectors plus independent interoperability for the frozen hybrid envelope; roundtrip tests alone are insufficient. Reject malformed/unsupported formats and missing PQ components without fallback.
- Wrong organization/resource/purpose/header, invalid encodings, unusable X25519 values, ML-KEM rejection and modified GCM tag tests; never release unauthenticated plaintext.
- Verify fresh nonce/key behavior during new encryption, idempotent storage retries, source/destination context binding and unchanged content ciphertext during rewrap.
- Authenticate and scope every internal operation; reject wrong/stale/revoked workload identity and portal-admin attempts to access custody APIs. Prove persistent private/root material is not returned by runtime endpoints or leaked through logs/queues.
- Test sealed startup, wrong/insufficient unlock authority, dependency timeout, service restart, selected custodian/hardware recovery and actual isolated restoration. Do not mark tests complete until the root-custody choice is implemented.
- Run real PostgreSQL concurrent reads/uploads/rotation/rewrapping, stale destination handling and interruption at every object/database commit boundary. Test root rotation separately from organization-key rotation; preserve retained backup reads.
- Verify deployed PQ transport on required browser/internal/recovery hops and safe unsupported-client behavior. Capture nonsecret evidence of negotiation.
- Prove deployment has no AWS KMS calls/permissions/settings dependency, including document storage, immutable archive, backup and infrastructure integrations. Replace legacy tests rather than claiming a mock validates the new boundary.

## Retained visitor submissions

The existing `test_assigned_staff_can_read_retained_file_after_recipient_access_ends` checks staff reads after revocation. Add independent cases for session timeout, logout, access expiry, valid-grant reverification on the same thread, expired/revoked grant denial, and preserved exact bytes/conversation IDs. Test concurrent staged cleanup/finalization, key-service restart, rotation, root migration and restore. No timed job or storage lifecycle rule may delete committed documents merely because recipient access ended. See [DATA_RETENTION.md](DATA_RETENTION.md).

Documentation-only changes are checked for consistency, links and distinction between target and observed behavior. They do not constitute a new backend, integration or production test pass.

## Self-managed key-service evidence (28 October)

Latest follow-up verification: **80 passed, 1 skipped** after consolidating the local/service hybrid implementation and adding malformed-envelope, fresh-material and sealed-service integration checks. The skipped check is the opt-in browser test, previously exercised separately; no UI changed in this follow-up. Ruff lint/format, Django system checks and migration consistency passed. This supersedes the earlier 73-test count below.

Install test dependencies with `pip install -r requirements.lock -r requirements-test.lock`. `pytest -q` includes real local HTTPS/mTLS, sealed restart, wrong-key rejection, concurrent rotation/read, idempotency, transaction rollback, encrypted SQLite backup restore, scoped Django integration and external primitive known-answer/interoperability checks. One published ML-KEM vector (count 999) and both decapsulation cases are pinned in `backend/tests/vectors/mlkem768.json`; this is not full ACVP certification. The educational kyber-py dependency is test-only. The custodian webpage was exercised in headless Edge through login, unseal, cleared input, seal and logout. See KEY_SERVICE_OPERATIONS.md for the optional browser command. Production review, PQ negotiation evidence, PostgreSQL concurrency, real deployment recovery and audit anchoring remain open.

Final local verification: `pytest -q` reported **73 passed, 1 skipped** (the opt-in browser check). Running that browser check separately reported **1 passed**. Ruff lint/format, Django system checks, migration consistency and tracked diff whitespace checks passed. PostgreSQL CI and live infrastructure checks were not run locally.

## Additional readiness evidence

`test_readiness.py` exercises archive identity/digest/retention rejection and projection rebuild, scanner protocol/outage handling, staged cleanup preservation/retry, disk/backlog signals, and ciphertext restoration/atomic replacement. `scripts/check_postgres.py` ran seven PostgreSQL 17 tests (six concurrency/locking cases and actual pg_dump/pg_restore). `scripts/check_browser.py` ran the full staff-request/recipient-upload/staff-read/admin-audit workflow with axe scans and keyboard focus checks. A passing synthetic scanner test is not a real antivirus result. The real ClamAV and AWS integration tests are explicitly opt-in; the ClamAV evidence below supersedes the earlier unexecuted status. AWS remains unexecuted. See OPERATIONS_RUNBOOK.md for commands and remaining evidence.

Final readiness evidence: full synthetic suite **90 passed, 9 skipped** before the additional atomic-write/deadlock cases; subsequent affected-flow/crypto/readiness run **63 passed, 1 skipped**, final readiness subset **11 passed, 1 skipped**, and isolated PostgreSQL suite **7 passed**. The full browser workflow passed with actual-content axe scans, modal/skip keyboard checks and CSRF-cookie-change regression. Frontend production build, format checks, Ruff and Django checks passed. At that earlier checkpoint, optional live AWS/ClamAV checks were not run; PostgreSQL cases skipped in SQLite were run separately against PostgreSQL 17. The latest minor UTF-8 punctuation correction was build-checked.

## Actual ClamAV verification — 2026-10-28

Full regression run with local socket access and `RUN_CLAMAV_INTEGRATION=1`: **122 passed, 9 skipped**. Real WSL Ubuntu ClamAV 1.5.4, official daily database 28167, and project scan-limit configuration were used. Checks covered clean and EICAR bytes, actual clean/malicious API uploads, unavailable connection without a new attachment, and rejection beyond the daemon's 26 MiB stream cap. Unit tests cover stale/future database timestamps, malformed VERSION/responses, and deadline exhaustion. Remaining skips concern separately gated integrations; they are not passes.

A separate exploratory compressed-file test did NOT demonstrate fail-closed nested expansion: ClamAV reported a ZIP with 105 MiB repeated text clean. ZIP upload is forbidden, but PDF embedded content and other parser edge cases need a reviewed corpus. This limitation is retained in the runbook. Docker/container CI and memory/load tests were not run locally.

Portal-boundary verification (2026-10-28): full regression run 125 passed, 12 opt-in tests skipped; final focused boundary tests 7 passed after disabling legacy recipient endpoints by default. Actual browser staff request/recipient upload/staff read/admin audit workflow passed with accessibility checks. TypeScript/build, formatting, Ruff and Django checks passed. Local API was restarted; recipient entry point responds and test-mailbox/legacy recipient endpoints return 404. No public production deployment or real email was verified.

## Connections and SMTP verification - 2026-10-28

Completed Connections screen with explanatory service cards, own-account delivery counts, sender-management permission links, refresh and a rate-limited live scanner health check. Backend tests verify account isolation, secret redaction, failed health checks and no email side effects. 35 focused tests passed; full staff/recipient browser flow plus desktop/mobile Connections and accessibility checks passed. Frontend build/format and Ruff lint/Django checks passed. Global Ruff format found a separately added scripts/start_local_maintenance.py formatting issue; this unrelated file was left unchanged.

The user authorized enabling the saved Private Email SMTP profile and resending one captured notification. SMTP authentication succeeded and that notification reached provider_accepted. The running API/worker now use SMTP; previous captured notifications were not bulk-replayed. Inbox receipt is not confirmed, and localhost invitation links still require this computer.

## Branded notifications and storage inspection - 2026-10-28

Protected/account notifications now include escaped branded HTML and a plain-text alternative. Ordinary-email behavior is preserved. 28 template/workflow tests passed, including unsafe-link rejection, HTML escaping and confidential subject/body exclusion. Local desktop/mobile previews were rendered; Gmail/Outlook rendering of the new template remains unverified. The SMTP worker was reloaded for future notifications; no extra test email was sent.

Read-only inspection of the current local dataset authenticated 2 encrypted subjects, 3 message bodies, 2 filenames, 2 file objects and 5 retained outbox payloads. All 14 used the v2 ML-KEM-768/X25519/AES-256-GCM envelope; altered in-memory copies were rejected. No plaintext, keys or live invitation links were printed or written by the inspection. Metadata such as addresses, timestamps and file sizes remains readable; this is field/object encryption, not whole-database encryption. Local root-key custody on the same machine is not production custody approval.

## Proxy/token-bucket regression (29 October 2026)

`pytest backend/tests/test_rate_limits.py backend/tests/test_proxy_integration.py`
checks refill/capacity/clock rollback, per-account isolation, trusted-peer parsing,
malformed and forged headers, and real login responses. The nginx integration
uses the shipped preview proxy configuration and a disposable Django live server,
with separate loopback source IPs. It verifies forged headers cannot replenish
anonymous limits and another client/account retains its allowance. CI installs
nginx and sets `REQUIRE_NGINX_TEST=1`, making missing nginx a failure there.
Locally, 43 focused/authentication/portal tests passed and the one actual-nginx
test was skipped because nginx is unavailable. CI execution remains pending.

The broader token-bucket run produced 161 passes, 13 skips and three local
key-service connection failures under the restricted network sandbox. Re-running
the key-service module with local socket access passed all 16 tests (one opt-in
skip). Root `.env` loading, precedence, literal secret handling, Compose
placeholder initialization and related workflow/rate tests subsequently passed
40 focused checks. The frontend build and Django system checks passed.

## P1 remediation verification — 29 October 2026

After the authenticated-wrapper and workflow changes, the full suite with local
socket access passed **181 tests, 13 skipped**. Six focused P1 tests then passed,
including a newly added negative Connections-configuration check. Coverage includes
public-key-only attachment/MFA forgery rejection, backup-before-rotation activation,
restore of a newly rotated key, backup failure rollback, inactive-owner blocking,
reactivation with fresh staff access, idle-session behavior and route/consent checks.
Reference interoperability now verifies the added MAC using a separate test-side
implementation; this is not an independent audit.

`scripts/check_p1_ui.mjs` uses intercepted synthetic browser fixtures (no mail or
real record writes) for stale route disabling, explicit Nophi consent, the expected
route payload, recipient 401 re-verification, draft text and uploaded-file reference
retention. TypeScript/Vite build and Ruff checks passed. Tests do not certify
production rollback resistance, off-host backup durability, threshold custody or
migration of existing unauthenticated envelopes. See P1_REMEDIATION.md.


## P2 verification — 2026-10-29

- Full backend run: 189 passed, 13 skipped; three loopback HTTPS integrations were blocked by Windows sandbox socket policy (WinError 10013).
- Those integrations were rerun with local socket access alongside flow/P2 regressions: 51 passed, 1 skipped.
- Final focused P2 run after quota cleanup and cache regression additions: 11 passed.
- Frontend TypeScript/Vite build passed; Ruff passed; Django migration drift check reported no changes.
- Intercepted-API browser checks passed: invalid address cannot submit, stale route stays blocked, explicit Nophi consent, 360 px recipient OTP/upload overflow checks, re-verification retains draft/files, and development inbox requires a memory-only operator capability and clears captured contents on lock.
- No real SMTP messages were sent. These runs do not establish production PostgreSQL concurrency, deployed nginx headers, full-stack 360 px key-service readiness, independent cryptographic review or successful migration of existing legacy envelopes.
- P2-10 remains partially remediated. See P2_REMEDIATION.md.


## P3 verification — 2026-10-29

Full synthetic regression suite: **198 passed, 13 skipped** with local test sockets permitted. Focused crypto/flow/P3 run: 57 passed. Frontend TypeScript/Vite build and Ruff passed. Browser fixtures confirmed current invitation history replacement, session-based reload, 360 px recipient flows, draft preservation and operator inbox locking. The optimization regression injects a failed handshake under python -O and confirms explicit failure detection. Rotation tests simulate a lost response after remote commit, then replay with the original operation ID and expected version.

Docker is unavailable on this host; the pinned non-root frontend container and actual nginx response headers still need a Linux deployment/build check. No live service restart, real email, legacy data migration or production approval is implied. See P3_REMEDIATION.md.
