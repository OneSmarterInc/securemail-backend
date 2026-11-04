# QA-06 through QA-09 remediation

## Audit archive

Schema-2 objects hold up to 1000 ordered events (16 MiB maximum), with an
organization-specific batch sequence and previous SHA-256 digest. Schema-1
objects remain readable. Pending canonical bytes and retention are saved before
network I/O; retries preserve the batch identity and bytes. A response lost after
S3 acceptance can create another locked version of the same bytes. Only the
verified version is referenced by the catalog. No old versions are deleted.

Each batch costs one put, one retention check and one verified version read.
The archiver uses a dedicated cross-process lock, drains up to 20 batches per
invocation, and immediately requeues while pending events remain. Beat checks
every 10 seconds as recovery from failed workers. S3 requests have bounded
connection/read timeouts and retries. PostgreSQL must use a direct or
session-pooled connection for advisory locks.

Monitor `securemail.audit` error `audit_archive_lag_exceeded`; route it to the
production alert system. Default threshold: 900 seconds. Audit API also reports
oldest_pending_seconds and archive_overdue. This code emits an alert signal;
an external paging destination has not been configured. A separately protected
manifest/checkpoint remains necessary to authenticate an archive chain and
prevent undetected truncation. Exported manifests support independent recovery;
rebuilding verifies the batch chain and caches one batch at a time.

Synthetic load regression: 5000 events, five objects, 15 S3 operations. It enforces
at least 1000 events/minute on the test adapter, not real AWS performance. Production
sign-off requires the same workload on actual PostgreSQL/S3 with network latency,
retention verification, worker failure/retry and oldest-event-lag monitoring.

## Public transport

Recipient TLS 1.3 prefers X25519MLKEM768 and accepts X25519. This classical fallback
is **not post-quantum protection**. Internal key-service and scanner policies are
unchanged. Staff endpoints still require the hybrid group; classical connections
receive only an upgrade explanation. TLS versions older than 1.3 still fail at
the handshake, where an HTTP message cannot be delivered.

The recipient nginx access log records connection ID, negotiated group and TLS
version, without URLs, tokens, cookies or addresses. Aggregate pilot support by
unique connection ID/group before deciding on a stricter public policy. This
supersedes prior public-recipient PQ-only release claims; at-rest crypto review
and internal PQ gates remain required. Real negotiation testing requires the
PQ nginx image; static routing checks alone do not prove negotiation.

## Login abuse control

50 attempts per source IP per minute and 10 per account/source network per minute
(IPv4 /24, IPv6 /64), checked before password hashing. Token buckets refill
continuously. Attempts from a different network do not drain a shared hard
account lock. Correct passwords still need MFA. The hard source restriction
applies even to correct passwords in an exhausted source network.

Known-account failure counters aggregate a 10-minute window. At 100 failures,
failed responses advertise exponential Retry-After (1 to 300 seconds); every
100 failures emits an audit event and warning for monitoring. This is advisory
backoff, not a worker sleep or an account-wide hard lock. Attackers can ignore
it. Distributed password-hashing load still needs edge throttling/challenges.
No global login bucket blocks all staff. Shared networks can still experience
localized denial of service: this is the explicit availability/security tradeoff.

## Staff sessions

15-minute idle timeout is configurable through STAFF_IDLE_SECONDS. Absolute
lifetime remains eight hours and step-up cannot extend it. Expiry is enforced
server-side on every authenticated request. Session polling never extends idle
life. A CSRF-protected authenticated activity endpoint updates last_seen.
The UI sends activity only after trusted keyboard/pointer/wheel/touch input,
shows a one-minute warning, and removes protected content at the confirmed
deadline even during network outages. Recipient session policy is unchanged.
Previously downloaded files cannot be recalled by a session lock.

Deploy migration 0020 before starting updated workers/web processes; restart beat
and workers to pick up the batch schedule. No existing archive is rewritten.
