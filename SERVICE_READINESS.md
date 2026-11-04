# Document sending and key-service readiness

> Scope update — 2026-11-04: the owner removed antivirus from the product. Uploads undergo file-type/size validation, authorization, encryption and integrity checks; no malware verdict is produced. Historical scanning results below do not describe current functionality. Other release gates remain.

New conversations/requests, ordinary sends (including Nophi), staff and recipient replies, and file uploads require a fresh authenticated key-service status. Sealed, unavailable, unconfigured, malformed, unknown-suite or audit-failed responses deny submission with HTTP 503 and:

```json
{"error":{"code":"service_disabled","message":"Service is disabled."}}
```

The UI polls `/api/document-service` (or `/recipient-api/document-service`) every five seconds and disables send/upload controls while displaying **Service is disabled.** Failure to fetch status also disables them. Draft input is preserved. UI status is advisory: direct API submissions are independently checked and cannot bypass the gate by enabling a button.

Uploads are checked before processing and again after scanning. Compose/reply transactions recheck before completion, rolling back their database changes if readiness is lost. Outbox jobs associated with conversations wait while disabled and retry later without an SMTP call. A final check before SMTP reduces the in-flight race; messages already accepted by SMTP cannot be recalled, and distributed preflight checks do not constitute an atomic seal/send transaction.

## Configuration

`KEY_STATUS_URL`, `KEY_STATUS_CA`, `KEY_STATUS_CERT`, `KEY_STATUS_KEY` default to the configured key-service connection. A separate certificate restricted to the `status` operation is preferred. `KEY_STATUS_REQUIRE_PQ=true` requires verified hybrid TLS even when the rest of the local app remains in synthetic mode. No custodian password or unseal key is passed to Django or the worker for readiness checks. Missing configuration fails closed; there is no runtime bypass flag.

The localhost app and worker now use Python 3.15 and a dedicated status-only identity under `.runtime/maintenance/readiness.*`. It cannot unseal, rotate, wrap or unwrap. `scripts/init_local_readiness.py` adds that synthetic identity to an existing local setup; restart the service to load the additional client CA. The local startup configuration includes these status paths. The service remains sealed until the custodian unlocks it at `/maintenance/`.

Existing local development documents still use the prior local protector. This readiness gate enforces sending availability; it does not migrate their cryptographic keys. Complete the separate import/migration procedure before claiming service custody of those keys. Production uses the actual service-backed protector in addition to admission control.

Status checks have a three-second connection timeout, are not positively cached in the backend, and expose only readiness plus the user message through the application endpoint. Account for identity rate limits and TLS-check capacity during production load testing. The existing production gate remains in force.

## Evidence

- Full synthetic suite after initial gate implementation: 152 passed, 12 skipped.
- Final admission/delivery tests: 11 passed, including a seal immediately before SMTP that defers without sending.
- Actual localhost status-only certificate authenticated over PQ TLS and returned sealed=true.
- Browser check used the live sealed status to verify disabled controls, then simulated ready/disabled transitions without sending or uploading anything.
- Frontend build, Python lint and formatting passed. No live unseal or real email was performed for these checks.
