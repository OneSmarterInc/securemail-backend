# P2 remediation record

2026-10-29. Source changes for synthetic use; production crypto review and the P1 legacy-envelope migration gate remain mandatory. Existing application services have not been restarted onto the incompatible authenticated-envelope format.

| Finding | Change | Remaining evidence or limitation |
| --- | --- | --- |
| P2-1 | Bootstrap requires SETUP_TOKEN_SHA256 capability and refuses after any staff account exists under the organization lock. Dev inbox requires a separate X-Dev-Inbox-Token matching DEV_INBOX_TOKEN_SHA256. Loopback grants no authority. | Both capabilities default disabled. Provision random tokens explicitly; do not reuse passwords. |
| P2-2 | Unavailable page explains that a newer reply may replace the link and directs users to the latest notification. | Older invitation URLs are still superseded. This is the requested explanation alternative, not token-history support. |
| P2-3 | Explicit SMTP connect/TLS/auth phase before submission; connection failure retries with capped exponential delay, maximum five attempts. Once submission starts, ambiguous transport failures remain uncertain. Close failures cannot undo confirmed acceptance. | SMTP still cannot guarantee exactly-once delivery; after-submission errors conservatively need review. |
| P2-4 | Audited reset_mfa action with reason, recent MFA, privilege-management permission, active target, and a different acting administrator. Clears seed/recovery hashes, invalidates sessions and pending invitations. UI action included. | Administrator must verify the staff member's identity independently before reset. Staff signs in with their password and enrolls a new factor. No self-reset bypass. |
| P2-5 | Explicit sender-address assignment requires can_manage_privileges; account creation still defaults to the new staff member's own company address. Existing permission updates retain their privilege check. | SMTP sender-profile approval remains independently required. |
| P2-6 | Global and fingerprint throttles before policy lookup; durable denials coalesced into at most one batch/minute outside the service lock. | In-memory pending denial counts can be lost at restart; next denial flushes a due batch. External aggregate metrics/alerting and deployment load testing remain needed. |
| P2-7 | secure_delete on key-store write transactions; root rotation performs checkpoint(TRUNCATE), VACUUM, checkpoint after commit. Response includes storage_cleanup_complete. | A false cleanup flag means rotation committed but cleanup needs operator attention. Snapshots, old backups, SSD remanence and filesystem copies are not erased. |
| P2-8 | Recovery/policy and key-store/backup/restore files created exclusively using os.open mode 0600 before writing. | POSIX mode enforcement does not replace Windows directory ACL provisioning. |
| P2-9 | PQ_TRANSPORT explicitly excludes unverified PostgreSQL, Redis, SMTP and onward email transport from the candidate PQ claim. | Classical TLS is not PQ. Complete required-hop scope approval remains a production gate. |
| P2-10 | Two-second, one-entry-per-thread public active-key metadata cache, invalidated on remote wrap errors and local rotation. Every wrap still checks authorization and expected active version at the service. | PARTIAL: cold metadata synchronization and some crypto/network calls remain inside business transactions; service wrap audits still write synchronously. A prepare/revalidate/commit refactor and PostgreSQL contention measurements are required before closure. |
| P2-11 | Security headers repeated alongside location-level Cache-Control in the local nginx API location. | Verify deployed nginx response headers as deployment evidence; templates alone are not proof. |
| P2-12 | Server idempotency for delivery retry, account actions and revoke; frontend keeps keys through uncertain responses and step-up. Payload changes are rejected for reused keys. | Records must outlive retry windows. API consumers must send Idempotency-Key. |
| P2-13 | Native form validity blocks uncommitted/invalid address text instead of silently dropping it. Blur/Enter validates and adds address chips. | Synthetic browser regression included. |
| P2-14 | Recipient end-to-end context and mobile viewport use 360 px. Synthetic browser drill covers OTP, upload and re-verification at 360 px with overflow checks. | Mocked browser evidence is not live deployment evidence; isolated full-stack drill needs a ready test key service. |
| P2-15 | Atomic per-grant/per-staff staged-byte reservation before reading/scanning; pending uploads count toward quota. Deleted and committed records do not. Failed uploads release reservations after object cleanup. Default quota 100 MiB; Django spools uploads over 1 MiB. | AES-GCM/scanner still operate on bounded whole-file buffers (maximum 25 MiB plus ciphertext overhead). Crash reservations fail closed until authorized staged cleanup; retained committed files are never age-deleted. PostgreSQL race/load evidence remains required. |

## Operator configuration

Root .env contains blank SETUP_TOKEN_SHA256 and DEV_INBOX_TOKEN_SHA256 placeholders. Generate two independent cryptographically random tokens (at least 32 characters), store their SHA-256 hex digests in the corresponding settings and keep the raw tokens in operator custody. SHA-256 here verifies high-entropy random capabilities; staff/custodian passwords retain their password hashing schemes. Enter the bootstrap token only in the setup form; send the separate inbox token only in the X-Dev-Inbox-Token header. Never put either token in a URL. Setup is consumed by successful first-account creation. The synthetic inbox capability is reusable and separately revocable by configuration rotation; it is not a bootstrap token.

STAGED_UPLOAD_QUOTA_BYTES defaults to 104857600. Pending/crashed reservations are included. Use the documented staged-cleanup dry run and approval procedure; it does not remove committed conversation documents.

## API changes

- POST /api/auth/setup: adds setup_token.
- GET /api/dev/inbox: requires X-Dev-Inbox-Token in addition to synthetic/dev-tool/development-mail settings.
- POST /api/admin/accounts/{id}: adds reset_mfa; all actions require Idempotency-Key.
- POST /api/delivery/{id}/retry and /api/conversations/{id}/revoke require Idempotency-Key.
- POST upload endpoints may return 413 / staged_quota; no scan or encryption starts when the quota is already exhausted.

## Validation

See TESTING.md for final run results. New regressions cover operator capabilities, MFA reset/session invalidation, sender permissions, SMTP phases, retry replay, staged quota, root sanitation and denial batches. No real email is sent by these tests.
