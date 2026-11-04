# P3 remediation — 2026-10-29

These are source changes, not production deployment approval. The earlier independent crypto review, trusted legacy-envelope migration and P2-10 lock-scope work remain open.

| Finding | Implementation | Verification / qualification |
| --- | --- | --- |
| P3-1 | Successful verification uses history.replaceState to replace the current entry with #/conversation. The token is retained only in current component memory for idle re-verification; reload resumes via the recipient session. No token is written to browser storage. | Synthetic browser verifies URL replacement and reload. Earlier separately visited copies of a URL and external email/history records cannot be erased by this page. |
| P3-2 | Frontend build and nginx base images pinned to official registry manifest digests. nginx runs as UID/GID 101 with PID and temp paths in /tmp, bypassing root-oriented entrypoint scripts. | Digests read from Docker Hub registry. Docker unavailable here: build/run as non-root on Linux remains unverified. Other service images are outside this frontend Dockerfile change. |
| P3-3 | Permissions-Policy, COOP and CORP added to local and HTTPS templates. Exact index.html location uses no-store and repeats security headers; SPA fallback redirects internally to it. | HTTPS candidate retains HSTS, including index.html. HSTS intentionally absent from HTTP-only localhost configuration. Deployed header checks remain required. |
| P3-4 | Unread dot has role=img and accessible name Unread. | Semantic accessibility fix; frontend builds. |
| P3-5 | All bare assert statements removed from the transport verification script and replaced with explicit RuntimeError failures. | Injected handshake failure remains a non-passing check under python -O. |
| P3-6 | Rotation CLI requires --request-id and --expected-active. Remote rotation API requires both; retries preserve the original expected version. Application records completed operation IDs, rejects changed arguments and returns the original key. Key service replay returns current metadata, never reactivates a later-retired version. | Tests cover lost response after remote commit, replay, changed parameters and replay after later rotation. Local automatic initial provisioning remains serialized under the organization lock. |
| P3-7 | Unexpected service errors log a correlation incident UUID and exception class; the 503 returns the incident UUID. | Regression ensures secret-bearing exception messages are absent. No request body, key, traceback locals or exception text logged. Deployment must collect stderr/logs and alert. |
| P3-8 | Owner/organization-scoped subject search decrypts in memory; also matches recipient and state. No plaintext index or persisted search terms. Search is rate limited and capped at 1000 candidate conversations after the state filter; larger scope returns explicit 422. | Owner isolation, case-insensitive subject matching and encrypted storage tested. Linear decrypt cost is a deliberate bounded approach; larger-scale encrypted search requires a separate reviewed design. Avoid logging query strings at deployment ingress. |
| P3-9 | Architecture table now matches explicit workload rewrap permission. Maintenance defaults rotate/import; custody is separate. | Documentation aligned with server/CLI allowlists; no permissions broadened. |
| P3-10 | Production example explicitly selects STORAGE_PROVIDER=local on a persistent EBS mount. Optional S3 alternative documented with SSE-S3 rather than KMS. Local storage adapter checks the selected provider explicitly. | Overall production environment remains blocked. Persistent mount, backups, restore, capacity monitoring and regional approval require deployment evidence. |

## Rotation operations

Create one UUID for the planned operation and retain it in the operator change record. Observe the current active version before dispatch. Invoke:

```text
python manage.py rotate_wrapping_key --organization ORG_UUID --reason "Scheduled rotation" --request-id OPERATION_UUID --expected-active ACTIVE_KEY_UUID
```

For first provisioning use --expected-active none. After an uncertain response reuse the **same operation UUID, expected version and reason**; do not discover the newly active key and substitute it into a retry. A distinct planned rotation gets a new operation UUID. Preserve operation records and service request records across restore. Old document ciphertext is not re-encrypted by rotation.

## Image provenance

Official Docker Hub manifest indexes resolved during this change:

- node:24-alpine: sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85
- nginx:1.28-alpine: sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236

Pinning is reproducibility, not a vulnerability attestation. Review updates and rebuild deliberately. The separate candidate PQ edge still requires its hybrid-capable nginx/OpenSSL build; the frontend image is the local HTTP preview image.
