# Performance review — 3 November 2026

## Scope and evidence

Reviewed frontend loading/polling/uploads, conversation and archive queries, attachment finalization, crypto batching, key-service connection management/storage, SMTP outbox, audit archival and container/nginx configuration. This is a code-path review plus an isolated query-cost experiment, not a production load certification.

The local app did not respond on localhost:5173 during this review. Failed connection timings are not application latency measurements. No real documents were read, no mail was sent, and no keys were unsealed for this review.

## Small improvement implemented

Historical messages without saved mail headers fetched the same recipient list separately for every message. `conversations.detail()` now loads the conversation's grants once and reuses them for summary, reply-all eligibility and fallback headers. BCC filtering is still applied separately for the viewer. No cross-request cache was introduced.

Synthetic SQLite experiment (decryption mocked to isolate database/serialization; one run per size, not a percentile benchmark):

| Messages | SQL before | SQL after | Before ms | After ms |
| --- | ---: | ---: | ---: | ---: |
| 10 | 14 | 4 | 17.1 | 6.6 |
| 100 | 104 | 4 | 60.7 | 18.4 |
| 500 | 504 | 4 | 281.2 | 104.6 |

These times exclude actual encryption, network and browser rendering. The deterministic improvement is constant SQL query count. New regression tests cover 10 and 100 messages. Throughput, flow and shared/private reply suites: 39 passed. Ruff checks passed. Initial sandbox attachment tests failed on Windows hard-link permissions; rerunning the isolated suite outside the sandbox passed without changing preservation behavior.

## Remaining priorities

### 1. Paginate conversation history before decryption — highest priority

`backend/apps/core/conversations.py:detail` loads every message, every attachment name and every delivery job. Both portals render the returned history. Threads are deliberately permanent, so this cost grows indefinitely.

There is already bulk decryption, but each remote batch holds at most 25 envelopes. With no files, 500 messages plus a subject need 21 batch operations; 5,000 messages need 201. These are operation counts, not measured latency estimates.

Implement newest-first cursor pagination (initial 25–50 messages), with older messages fetched on demand. Apply recipient visibility filtering before pagination. Keep deterministic `(created_at, id)` ordering, preserve drafts and scroll position, and expose notification history through a separate paginated endpoint. A new reply should update the latest page instead of refetching/decrypting the entire conversation.

Tradeoff: API and both portal clients must change together. Do not truncate history silently or change the permanent-thread policy.

### 2. Shorten attachment submission transactions — highest priority

`save_reply`/compose hold an organization lock while `attach_files` reads and decrypts staged files, creates encrypted evidence bundles, re-encrypts each attachment for its final message context, and writes storage. Evidence embeds base64 file data inside another encrypted bundle, adding copying and storage work. Multiple files are finalized serially.

Use a durable finalization state machine: claim authorized staged objects briefly, prepare encrypted final objects outside the organization lock, then recheck ownership, permissions, revocation, readiness and idempotency in a short commit transaction. Retain rollback/orphan cleanup and preserve original provenance. Scope locks to the affected thread/attachment where invariants allow it.

Tradeoff: moving I/O outside transactions without durable claims and final authorization checks introduces races. This needs failure/concurrency tests; simply deleting locks is unsafe.

### 3. Dispatch notifications promptly and with bounded concurrency

`settings.py` schedules outbox work every 10 seconds. `mail._process_batch` processes up to 100 jobs serially with a 30-second admission deadline; individual SMTP connections have a 20-second timeout. A slow provider can delay unrelated recipients and OTPs. The deadline does not interrupt an already-running SMTP call.

After committing a delivery job, wake a worker immediately; retain periodic database reconciliation for broker failures. Add a priority lane for OTPs and bounded per-provider/per-sender concurrency. Preserve transactional claiming and the uncertain-delivery state; never retry an ambiguous SMTP submission blindly. Measure enqueue-to-start separately from SMTP/provider latency.

Tradeoff: successful SMTP submission cannot guarantee inbox delivery. Additional concurrency must respect provider limits.

### 4. Reduce repeated readiness traffic

`frontend/src/api.ts:useDocumentService` polls every five seconds per mounted consumer, with no shared subscriber or hidden-tab suspension. Each server check reaches the actual key service. At 50 active consumers that is about 600 status requests/minute before document operations, ignoring request duration.

Share one UI status subscription per portal and pause it when hidden; refresh on focus. Keep authoritative readiness and unwrap checks on server operations. Never use a UI status cache as permission to decrypt or send while sealed.

### 5. Optimize key-service work after measuring it

Persistent mTLS pooling already exists (four leases per pool), as does request-local envelope deduplication. The client drops connections after one second idle; the server idle timeout is two seconds, so reuse is mainly within bursts. `Store.transaction` opens SQLite and takes a global lock with `BEGIN IMMEDIATE` and durable commits. Batches serialize their crypto/audit work under that lock.

Instrument pool wait, handshake, cryptographic operation, SQLite lock wait and commit duration. Tune coordinated connection lifetime/capacity only with idle-peer exhaustion and custodian-capacity tests. Reduce operation counts first. If durable group commit is later required, acknowledge requests only after their audit batch is durable; do not replace synchronous audit durability with an unprotected background buffer.

Earlier CI artifact, 31 October (not rerun here): synthetic PQ key-service component, concurrency 50, 650 batch calls, 14.18 seconds total, p95 2.908 seconds, zero errors. It simulated 50 staff opens and 500 recipient opens, not 550 simultaneous users or a complete portal deployment. This suggests queueing deserves measurement; it does not establish today's page latency.

### 6. Secondary opportunities

- Downloads unwrap content and filename separately; batch these within the authorized request while preserving integrity verification and audit.
- Search-index post-save handlers decrypt newly encrypted subjects/names. Pass already-available plaintext explicitly when creating records, while retaining a safe fallback for other writers. Do not retain plaintext in a cache.
- Archive document paging and keyed token search already limit decryption to the selected page. Use PostgreSQL `EXPLAIN (ANALYZE, BUFFERS)` on representative synthetic data before adding indexes; date-string/substring search and sender expression sorting warrant inspection.
- Frontend uploads are sequential. Consider a small bounded queue after measuring scanner capacity and memory. Do not parallelize unlimited memory-resident uploads.
- The inspected nginx configs do not explicitly enable static asset compression or immutable caching for hashed assets. Optimize public JS/CSS separately; protected API responses and downloads must remain `no-store`. Do not enable response compression indiscriminately on secret-bearing responses.
- Initial workspace rendering waits for `/auth/session`. That endpoint does not call the key service. A slow workspace spinner needs session/database/proxy timings rather than assuming AES is the cause.
- Audit archival already batches/drains with a bounded loop and monitors lag; measure it before replacing it based on older review findings.

## Verification plan for the larger changes

1. Add privacy-safe timings with request IDs: database duration/count, key-service calls and pool wait, storage, scanner, response serialization and outbox queue age. Never log content, filenames, email addresses, OTPs, keys or credentials.
2. Run the built stack with PostgreSQL, real key service and ClamAV against synthetic 10/100/1,000/5,000-message histories and mixed-size attachments. Capture warm/cold p50/p95/p99, errors, memory and worker saturation.
3. Compare isolated optimizations against the same workload. Proposed targets to validate: latest-page p95 below one second and text-only submission p95 below one second; measure file scan/finalization and external email delivery separately. These are targets, not current results or guarantees.
4. Re-run seal/revocation/BCC/privacy, concurrent replies, attachment integrity, crash recovery and idempotency regressions. No performance change should weaken these controls.

Recommended implementation order: latest-page conversation API/UI, attachment transaction shortening, prompt/priority outbox dispatch, shared readiness polling, then measured key-service/runtime tuning. Independent security review and existing production release gates remain open.


## Implementation update — 3 November 2026

Implemented in this checkout:

- Conversation endpoints return the newest 50 authorized messages, with signed, conversation/grant-scoped history cursors. Visibility filtering precedes pagination. Older messages load on demand; the recipient document archive has an independent authorized, paginated endpoint, so older files remain available. Cursor validity is 24 hours; this does not expire invitations or content.
- One grant query is reused across message headers. Delivery details are capped at 100 with aggregate counts and on-demand history. Downloads batch content/name unwraps within the request.
- Staged-file reading, decryption and evidence capture happen before taking the organization submission lock. Each attachment remains locked during its preparation. Final submission rechecks authorization/state/fingerprint; final message-bound encryption and storage still occur within the existing commit transaction. This reduces lock time, but is not a complete asynchronous finalization state machine.
- Committed notification jobs trigger best-effort Celery wakeups; OTPs have higher Redis queue priority. Worker prefetch is one. Periodic durable-outbox reconciliation remains. A five-second process-local broker failure backoff prevents large recipient lists from repeatedly blocking on an unavailable broker. Contending wakeups may defer to reconciliation. Running SMTP calls are not preempted; provider concurrency limits and isolated OTP workers still require deployment tuning.
- One shared display-status poll per browser application, every 15 seconds while visible, refreshed on focus. Backend custody checks remain authoritative; no cross-request DEK cache was introduced.
- Public hashed assets get one-year cache expiry and JS/CSS compression in nginx profiles. Protected responses retain existing no-store controls.
- Request-local numeric instrumentation measures total, database, key-service call, storage and scanner time/counts. Slow-request logs include endpoint function and request ID, not SQL, payloads, filenames or credentials. It does not yet split TLS/lock/pool wait into separate phases or measure streaming response time.

Deployment: apply migration `0023_message_history_index`, rebuild frontend/nginx, and restart API/Celery workers. `OUTBOX_IMMEDIATE_DISPATCH` defaults on outside synthetic mode; enable explicitly in a synthetic environment only with Redis and a worker. `PERFORMANCE_TIMINGS=1` and `PERFORMANCE_LOG_THRESHOLD_MS=250` control instrumentation.

Remaining measurement-dependent work: full PostgreSQL/real key-service/ClamAV load profiles; pool/SQLite tuning; durable asynchronous attachment finalization; explicit plaintext handoff to search indexing; provider-specific concurrency; and bounded parallel uploads. Security review/release gates remain unchanged. Local regression/build results are not production latency claims.


### Local verification results

- Full backend suite: **371 passed, 17 skipped**, 293.30 seconds (Python 3.14.7, Django 5.2.18, isolated SQLite/synthetic providers). Live PostgreSQL, ClamAV, nginx and other service-dependent checks remain skipped. The 600-rotation durable snapshot regression accounts for much of the runtime.
- Final focused performance tests including the subsequently added privacy-safe timing-log test: **10 passed**. Histories of 100, 1,000 and 5,000 messages each decrypt only the latest 50 bodies plus subject (without attachments) on initial load.
- Browser regressions with mocked APIs: **11 passed** for recipient layout/archive, conversation controls, table sorting/download, draft refresh and session outage handling. Updated recipient test with explicit older-history loading also passed.
- Frontend production build, targeted Ruff checks and migration consistency check passed. A full-tree formatting check also encountered unrelated integration files being edited concurrently; those files were not reformatted as part of this performance change.
- No production latency claim, live SMTP send, deployment or live database migration was performed by this change. Separate integration edits coexist in the working tree; they have not been bundled into a performance commit or push.
