# Small-host demo profile

`deploy/low-memory/` contains optional systemd drop-ins for a roughly
1.3 GB host. It is not a verified capacity guarantee or production approval.
Production gates remain in force. Do not bypass them for real confidential
data or replace the isolated key service with local keys.

## Changes

- One Gunicorn worker, two request threads; one Celery solo worker with prefetch 1.
- Beat remains separate so periodic delivery recovery and cleanup continue.
- New uploads: 5 MiB combined per message, at most 10 files. Staff and recipients
  get the configured limit from the same status request already used by the UI.
- PostgreSQL: 32 MiB shared buffers, 2 MiB work memory, 20 connections.
- Redis keeps AOF durability and uses `noeviction`: queued work is not evicted
  to save memory. Broker failures retain the existing database-outbox fallback.
- No plaintext upload spooling, weakened authentication, decryption cache across
  requests, antivirus replacement, or custody bypass is introduced.

Normal deployments retain their 25 MiB limit unless `MAX_UPLOAD_BYTES` is set.
Existing larger files remain downloadable. Their decryption memory must still
be included in capacity testing. The smaller staged quota affects new uploads;
it does not delete saved documents.

## Candidate memory ceilings

| Service | MiB |
| --- | ---: |
| API | 352 |
| Background worker | 192 |
| Beat | 80 |
| PostgreSQL | 128 |
| Redis | 48 |
| nginx | 24 |
| Total steady-state containers | 824 |

Run migrations separately before application workers start. API/worker/beat
ceilings are provided as systemd drop-ins; database, Redis and nginx entries
are planning budgets requiring separate configuration. These are experimental
ceilings, not observed usage. At
1.3 decimal GB (~1240 MiB), only ~416 MiB remains for Linux, Docker, the isolated
key service and other agents. That may be insufficient. Include every key-service
process in measurements. These drop-ins do not deploy that service.
Application service swap is disabled by MemorySwapMax=0. Do not compensate
with plaintext host swap for confidential workloads.

## Apply to the standalone backend

Use the existing service files and environment described in DEPLOYMENT_GUIDE.md.
For an isolated, approved rehearsal, place these values in the existing protected
`/etc/onesmarter/backend.env` (do not replace its other settings):

```dotenv
MAX_UPLOAD_BYTES=5242880
STAGED_UPLOAD_QUOTA_BYTES=20971520
```

Install `deploy/low-memory/api.conf`, `worker.conf`, and `beat.conf` respectively
as `/etc/systemd/system/onesmarter-api.service.d/low-memory.conf`,
`/etc/systemd/system/onesmarter-worker.service.d/low-memory.conf`, and
`/etc/systemd/system/onesmarter-beat.service.d/low-memory.conf`. Create those
service directories if absent, then run `systemctl daemon-reload` and restart
those three services during a maintenance window. No server was modified here.

Configure PostgreSQL shared_buffers=32MB, work_mem=2MB,
maintenance_work_mem=32MB, max_connections=20, and Redis maxmemory=16mb,
maxmemory-policy=noeviction, appendonly=yes through their existing configurations.
These affect shared services: use a dedicated demo instance and validate them
before applying. Do not change database durability or authentication settings.
Build the frontend in CI/Vercel, not on the small API host.

Measure systemd services with `systemd-cgtop` and `systemctl show` properties
MemoryCurrent, MemoryPeak (where supported), and NRestarts, plus cgroup
memory.events. For Docker deployments the included
`scripts/measure_container_memory.py --seconds 180 <container IDs>` samples
memory/CPU and reports final OOM state. The sampler is not an automated workload.

To revert, remove only these three drop-ins, remove the two optional environment
overrides, reload systemd and restart the services. Restore the previous
PostgreSQL/Redis tuning if changed. S3 stores bytes but does not remove RAM costs.

## Required target-host acceptance

While sampling, upload a 5 MiB file, send it, verify a recipient by OTP, reply
with multiple files totaling 5 MiB, and download/compare the original bytes.
Repeat with two concurrent users, login/MFA, a large retained document, and
notification delivery. Check seal/unseal denial remains enforced. Record request
p50/p95 and email queue delay against the normal profile on the same hardware.

The sampler prints memory/CPU observations and final OOM state. Samples can miss
brief peaks: also inspect cgroup v2 `memory.peak`, `memory.events`, container
restart counts and host `MemAvailable` before/after; fail on any new OOM event,
restart, lost job, byte mismatch or unacceptable latency. Run at least a 15-minute
soak and test startup and Redis AOF rewriting. Do not certify fit from idle RAM.

One background job runs at a time. Long SMTP/archive operations can delay OTPs;
two web threads also bound simultaneous requests. This preserves features but
cannot guarantee unchanged speed under concurrent load. If measurements fail,
increase RAM or move services off-host rather than weakening security.

## Local evidence

28 targeted backend tests passed, including an actual 5 MiB encrypted recipient
upload/reply/staff download, oversize rejection, retained-file download after
lowering the limit, no plaintext temporary uploads, and sealed-service checks.
Five browser regressions passed (upload limit and draft refresh); TypeScript and the frontend build passed. Docker is unavailable on this workstation:
Systemd startup, Linux hard-limit peaks and throughput remain unverified.
Standalone backend publication checks: 22 targeted tests passed, including the
5 MiB roundtrip and configured-limit endpoint; changed Python files passed Ruff.
Frontend publication checks are recorded in its separate commit.
