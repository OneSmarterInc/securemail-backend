# Decryption throughput and release gate

## Implemented behavior

- Thread details authorize/filter messages first, then batch the subject, visible bodies and attachment names. A 40-message/20-file thread uses three unwrap-batch requests rather than 61 individual unwraps.
- Bulk decryption deduplicates identical ciphertext/context pairs within the call. Nothing caches plaintext or unwrapped DEKs between HTTP requests. Sealing still prevents subsequent key operations.
- Each process uses a bounded pool of four mTLS connections per identity/configuration, sharing one TLS context. Admission is FIFO, with at most 64 waiting calls. Eight identities/configurations can be cached. TLS file replacement changes the pool identity; idle connections are refreshed after one second and connections have a 60-second maximum reuse lifetime. Ambiguous network failures are not automatically retried.
- HTTP/1.1 keep-alive retains per-request allowlist, scope and seal enforcement. Idle sockets time out after two seconds. Pre-handshake capacity is separate from authenticated and reserved custodian capacity.
- Batch unwrap retains one SQLite FULL-synchronous transaction and one chained audit record covering the count, key versions and request digest. Keys are returned only after commit. This is durable group commit, not a lossy background audit buffer; SQLite remains a single-writer service.
- Staff archive queries filter and paginate in SQL before decrypting at most 25 names and 25 subjects. Conversation search also paginates before decryption.

## Search migration and tradeoffs

Run `python manage.py migrate` and `python manage.py rebuild_search_index` with key access available. Original documents and ciphertext are not modified. Unreadable records remain unindexed and are reported; searches fail explicitly for an incomplete authorized index rather than silently omitting records. Normal date-ordered listing does not require a complete search index.

New records receive HMAC-SHA256 tokens for case-folded Unicode words, scoped to the organization. Search matches words, not arbitrary substrings. Filename and subject sorting is removed; date and sender sorting remain, as approved. HMAC tokens reveal equality/frequency and access patterns, but not readable words or alphabetical order. A holder of the dedicated SEARCH_INDEX_KEY can test guesses: this index is not equivalent to content encryption. Keep that secret separate from database backups. Synthetic environments default to the application secret; deployments must provision a dedicated stable secret. Rotation requires a maintenance rebuild; do not run searches against a mixed-key index.

The index is an optimization, never an authorization source. Ownership and recipient visibility still come from the original queries. Renames, future bulk imports and bulk ORM writes must explicitly rebuild/invalidate tokens; current filename/subject creation paths are indexed through model saves.

## Reproducible component gate

Set APP_ENV=test and DJANGO_READ_DOT_ENV=false, then run:

```text
RUN_KEY_SERVICE_LOAD=1 python -m pytest backend/tests/test_keyservice.py -k load_gate -q
```

PowerShell: set `$env:RUN_KEY_SERVICE_LOAD='1'` before invoking Python. The test uses a disposable real HTTPS/mTLS key service and database, 61 distinct wrappers for each of 50 staff-sized opens and three for each of 500 recipient-sized opens, with 50 concurrent tasks. It verifies all returned keys, audit-chain consistency and refusal after sealing. It requires zero errors, p95 below 30 seconds and total below 120 seconds. Results contain aggregate metrics only in `.runtime/key-service-load.json`.

Observed Windows synthetic component run on 2026-10-31: 650 batches, 10.557 seconds total, p95 2.499 seconds, zero errors. This run used classical TLS 1.3; it is not a PQ transport or full portal load result. The PQ CI job runs the same gate with RUN_PQ_TRANSPORT=1 and publishes aggregate metrics to its log. Its remote result has not been observed locally.

## Production release gate remains open

Run a sustained full-stack workload on deployment-equivalent hardware with PostgreSQL, actual PQ transport, nginx, scanner and workers: 50 active staff and 500 recipient sessions, realistic thread/file distributions, search, upload, download, OTP and outbox delivery. Record p50/p95/p99, errors, queue waits, CPU/memory, handshake counts, audit commit latency, and restart/seal/rotation behavior. Include a heavy-user fairness scenario and maximum-length threads. A finite synthetic component burst does not establish sustained capacity, 550 simultaneous portal sessions or production readiness. Keep this gate open until those results and the independent crypto review are approved.
