# Readiness operations and evidence

> Audit storage decision — 2026-11-04: staff/admin activity logs remain in the same
> application PostgreSQL database on EC2. External audit archival code is removed; no audit bucket or second automatic
> audit copy is required. Earlier mandatory S3/Object Lock audit requirements are
> superseded. Database logs are not immutable against privileged administrators.
> Key-service security journals, recovery snapshots and cryptographic release
> gates remain separate and unchanged. See [DATABASE_AUDIT.md](DATABASE_AUDIT.md).



> Scope update — 2026-11-04: the owner removed antivirus from the product. Uploads undergo file-type/size validation, authorization, encryption and integrity checks; no malware verdict is produced. Historical scanning results below do not describe current functionality. Other release gates remain.


Updated 2026-10-28. Synthetic/local verification is not approval to deploy real documents. Preserve the production startup gate. Run operational commands from the repository root with the intended environment. Never paste credentials into logs or evidence bundles.



## Audit archive



New archives contain a versioned organization-bound event envelope. The worker confirms COMPLIANCE retention, reads the exact returned S3 version, compares its SHA-256 and verifies event identity before saving the archive receipt. Failed confirmation leaves the event pending. Existing pre-envelope archives require an explicit format migration/recovery adapter; do not delete their only copies. No live archive data was migrated in this change.



`python manage.py audit_archive_evidence --manifest NEW_MANIFEST.json` exports version IDs, digests, retention and pending count. Copy/protect this manifest independently; it is unsigned, and a digest inside a tampered manifest is not a trust anchor. Exports are bounded by the available operator memory and should be partitioned before large deployments. To rebuild a separate searchable SQLite projection from a trusted manifest: `python manage.py audit_archive_evidence --manifest TRUSTED_MANIFEST.json --rebuild NEW_PROJECTION.sqlite3`. Existing destinations are never overwritten; canonical application audit events are never modified. This is a recovery projection, not automatic reconstruction of all application accounts/conversations.



The optional `backend/tests/test_live_archive.py` drill requires `RUN_AWS_ARCHIVE_INTEGRATION=1`, `AWS_REGION` and an explicitly authorized `AUDIT_TEST_BUCKET` beginning `onesmarter-readiness-`. It creates a synthetic version locked for one day, verifies that ordinary version deletion works on an unretained control, and checks denied retained-version deletion/retention shortening plus preservation when a newer version is uploaded. It deliberately leaves the retained version until its retention expires. Use a dedicated Object Lock bucket with no default retention, never the production archive. This test has NOT been run here. Production policy must also deny bypass through alternate identities and protect the independent manifest/checkpoint.



## PostgreSQL concurrency and restore



`python scripts/check_postgres.py --postgres-bin PATH_TO_POSTGRES_BIN` creates a fresh password-protected loopback-only cluster on port 55439, runs tests, and stops its own cluster in a finally block. It never uses the existing application database. Synthetic artifacts stay under `.runtime/postgres-check-*`. Matching PostgreSQL tools are required; tests never substitute SQLite for row-lock evidence.



Tests cover simultaneous OTP consumption, duplicate submissions, competing last-admin removals, recipient reply/revocation, lock-timeout rollback and explicit retry. The restore test uses real pg_dump/pg_restore to a new database and verifies retained conversation ciphertext, private-key records and audit mutation rejection. Test teardown temporarily permits TRUNCATE only in disposable `test_*` databases; audit triggers remain enabled throughout application test operations. A forced PostgreSQL deadlock rollback and complete retry also passed. Load/soak testing and a coordinated production recovery ceremony remain outstanding.



## Monitoring and cleanup



Run `python manage.py operations_check --max-archive-age-seconds SECONDS --min-free-bytes BYTES` using approved thresholds. It prints nonsecret JSON and exits nonzero for overdue archive work, missing archive/scanner configuration, low disk space or uncertain/stalled delivery. It is a probe, not an installed alerting system. Connect its failure to a named on-call owner; credentials, user filenames and message contents must not enter alerts. It does not certify scanner freshness, backup success or external storage enforcement.



`python manage.py cleanup_staged_uploads --older-than-hours HOURS --limit 100` is dry-run by default. Add `--apply` only after approving the abandoned-upload age. Cleanup serializes with finalization through organization/attachment locks, durably marks uncommitted rows cleanup_pending, deletes the object, then records completion. Failed external deletion is retryable. Committed attachments are never candidates, including after visitor expiry/revocation. Detached orphan objects without an attachment row, old migration objects and backups are intentionally not collected: they need inventory and an approved recovery-safe policy. No scheduled cleanup was enabled.



## Recovery ceremony and rollout



1. Assign an incident owner, custodian, and backup custodian; approve RTO (restore time) and RPO (acceptable data-loss window). Values remain undecided.

2. Preserve a coordinated PostgreSQL backup, ciphertext-object backup, encrypted key-store backup, configuration/PKI and trusted audit manifest. Keep recovery secrets separately. A backup on the application instance is not protection against loss of that instance.

3. Restore into isolated infrastructure with delivery disabled. Restore database/object identifiers, use the matching key-store version and unseal through the custodian page. Verify representative retained document bytes and their conversation/owner relationships; test expired visitors remain denied.

4. Rebuild and verify audit projection from independently protected version evidence. Measure gaps and establish a recovery point before accepting new writes.

5. Record restoration timing/data-loss window and verify alert delivery to the assigned owner. Approve cutover only after reconciling writes made since backup. Rollback requires a compatible schema/application image and consistent database/object/key state; restarting an older image alone is not a rollback plan.



Local tests cover encrypted object restoration, key-store backup/unseal/root recovery and a separate PostgreSQL restore. They do not establish combined infrastructure RTO/RPO, off-instance backup durability or actual custodian availability. Persistent storage belongs on the selected application-instance data volume; capacity, mount checks and deletion-on-termination configuration must be verified during deployment.



## Accessibility/browser assurance



Install frontend dependencies and a supported Playwright browser, then run `python scripts/check_browser.py`. It creates isolated synthetic servers and a database, executes the complete staff request/recipient upload/staff read flow, and stops its own processes. Axe scans check staff document, recipient, account directory/create dialog, audit and mobile views; keyboard checks cover dialog Escape/focus return and skip navigation. Artifacts are private under `.runtime/browser-check-*` and include synthetic sessions; do not publish that directory.



Low-contrast avatar initials and lost focus after closing dialogs were corrected. Automated checks do not replace screen-reader testing (NVDA/VoiceOver), zoom/reflow, other supported browser engines and a comprehensive independent accessibility audit. No such manual audit is claimed.



## Mail configuration selected by the user



Private Email uses the root environment configuration with STARTTLS on port 587. `EMAIL_HOST_PASSWORD` is the only supported password source; `EMAIL_HOST_PASSWORD_FILE` is rejected. Use the ignored root `.env` locally or inject the variable through deployment secrets. API and worker need matching configuration. The exposed credential requires provider-side rotation; the local password variable is intentionally blank until the replacement is supplied. See ENVIRONMENT.md for restart and migration constraints.



`python scripts/with_mail.py check` validates Django startup with the local profile without sending. Loading it for a worker can send queued jobs: use a separate reviewed test queue and approved recipients first. `python scripts/with_mail.py runworker` is available for an explicitly intended synthetic SMTP test; it has NOT been started here. The Compose profile has not been switched to live email. Staff-specific From addresses still need provider authorization or a reviewed sender-mapping policy; a single mailbox credential is not authority to impersonate every staff address. Real delivery, bounce handling and provider-limit evidence remain pending.



Browser repeat testing also identified a concurrent-session CSRF token/cookie mismatch. The client now takes the token from the current CSRF cookie for each request, with the response token as fallback; backend CSRF enforcement remains enabled. The browser regression explicitly changes the cookie after session initialization and successfully completes recipient verification.





## V2 remediation rollout



Read V2_REMEDIATION.md and KEY_MANAGEMENT.md before deployment. Back up the application and key service under approved custody, inventory legacy unauthenticated envelopes and pre-ledger MFA enrollments, apply Django migrations (0007 adds recipient session creation time), and deploy the key service before the application bulk-read client. Existing workload `unwrap` permission authorizes bounded batch unwraps. No plaintext fallback exists if the service is outdated or sealed.



Configure `--backup-directory` explicitly on the service to independent storage. Initialization alone no longer selects a local backup folder. New root/wrapping/MFA-key changes fail closed without this target. Three managed snapshots are retained; root rotation removes managed older-root snapshots only after new snapshot commit. Check cleanup indicators and reconcile all externally retained copies. Pending files cannot be blindly restored; a crash after commit may leave a pending committed generation requiring investigation.



Run Celery worker and Beat for scheduled transient cleanup. Monitor failed staged deletions, stale reservations, database growth, service bulk-budget denials, snapshot failures and cleanup flags. The bulk certificate budget is 120 batches/minute (maximum 25 unwraps/batch), separate from individual-operation budgets; production capacity and fair sharing still require load tests. Login admission uses a per-account token bucket with capacity 10 and a 60-second refill period (one attempt restored every six seconds), plus a separate 50-attempt per-IP bucket with the same refill period. There is no global login bucket. All attempts count before password hashing, including correct passwords; exhausted accounts must wait for refill. Email case normalization and the account-wide bucket prevent IP rotation from bypassing the account limit. Calibrate shared-NAT capacity before production.





## Exact company mailbox exceptions



`COMPANY_EMAIL_ALLOWLIST` is a comma-separated set of exact approved addresses. These addresses are eligible for company account creation, sign-in, session validation, authorized sender assignment and internal-recipient routing. It does not grant a role, bypass MFA or automatically create accounts. The normal organization domain and account permissions still apply. An SMTP profile is required for each sender; credentials remain environment-only. The local Proton configuration uses info@kormic.ai, STARTTLS port 587 and an exact profile. Deploy the same settings and restart the appropriate processes to adopt configuration changes.

# Audit sequencing and outbox batches (30 October 2026)



`AuditSequence` holds the per-organization audit counter separately from the organization row. Audit insertion and counter advancement remain in the caller's transaction. Business authorization, key rotation and idempotency still retain their own organization/resource locks; this is not a claim that all organization serialization has been removed. Organization business locks use PostgreSQL `FOR NO KEY UPDATE` so unrelated audit foreign-key inserts can proceed.



Deploy migration `0010_separate_audit_sequence` with **all API and worker writers stopped**. It seeds each counter from the greater of the legacy organization counter and existing audit sequence maximum. Do not run old and new application versions concurrently across this cutover. Run `python manage.py migrate --noinput`, then restart API, workers and beat together. A rollback must likewise stop writers and reverse the migration, which copies counters back to the legacy field.



Every `process_pending` batch, including direct CLI calls, takes a nonblocking PostgreSQL session advisory lock. Overlapping calls return without processing jobs; the lock releases on normal exit, exceptions or DB connection/process termination. Worker DB connections must be direct or session-pooled: **transaction-mode PgBouncer is unsupported for this lock**. Synthetic SQLite uses an OS-held file lock on the shared runtime mount. Different runtime mounts do not coordinate synthetic workers. Beat keeps its ten-second cadence but messages expire after ten seconds to avoid a backlog of obsolete ticks.



A batch admits at most 100 due jobs and stops admitting more after 30 seconds (an in-flight job can finish later). It checks document-service readiness once at batch start, outside database row locks. Readiness is a snapshot, not continuous authorization: sealing after admission does not recall a notification already prepared. Actual envelope decryption remains enforced per payload/file and may still contact the key service. Each job still claims its own database row and validates current actor, grant, conversation and sender policy; SMTP submission occurs outside DB transactions. Audit writes lock the sequence row, not the organization row. No email delivery guarantee or load-test result is implied by these changes.

