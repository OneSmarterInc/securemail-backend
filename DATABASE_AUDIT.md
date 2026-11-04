# Audit history in the application database

Owner decision, 4 November 2026: one operational copy of staff/admin audit history
in the same PostgreSQL database as the application on EC2. No S3 audit bucket.

## Configuration

Remove obsolete AUDIT_ARCHIVE_*, AUDIT_BUCKET and AUDIT_RETENTION_DAYS entries
from backend.env. They are no longer read; even stale values cannot enable S3.

AWS_REGION is unnecessary with local document storage and database-only audit history.
Keep APP_ENV=production, strict TLS, key-service protection and custodian unseal.
Existing audit rows need no migration and are not deleted by this change.

The archive writer, verifier, Celery task and archive command are removed.
No archive task is scheduled. Old queued task names are unregistered and discarded
by Celery; they cannot write to S3.
Stale bucket settings do not activate archival. Readiness reports database storage,
zero pending external archival and no false archive-lag alerts. The administrative
log page retains search, filtering and sorting without claiming cloud immutability.

Ordinary portal users cannot edit/delete audit history. Existing database append-only
restrictions remain. A privileged database/server administrator can defeat those
restrictions; host/disk loss may destroy the single copy. There is no WORM claim.

There is no external audit adapter or enable flag. Historical archive model/table
and migration definitions remain only to preserve existing data and schema history;
they have no active writer. Existing S3 objects are not deleted by this change.
Compatibility API fields report archive_enabled=false and zero backlog.

This decision applies to application activity logs. The key service retains its own
security journal in its sealed-store architecture, custodian records and recovery
snapshots. It cannot depend on application PostgreSQL availability for integrity or
unseal. No encryption/root recovery safeguards were removed. Explicit audit exports
remain available on request; no automatic duplicate audit archive is produced.

## Deployment

Install the new backend release at /var/www/securemail-backend/current, preserve the
existing backend.env and all cryptographic material, and remove the obsolete settings listed above.
Restart API, worker and beat if already running so all processes load the new mode.
Do not restart the key service solely for this change. Run deployment checks and
review the migration plan before applying pre-existing pending migrations.
The frontend main also updates the audit-page explanation; deploy it on Vercel.

## Local validation of this change

- Backend regression suite: 590 passed, 19 skipped (Python 3.12, SQLite).
- Focused production-startup/database-audit/readiness checks using the actual
  Python 3.15 hybrid TLS runtime: 22 passed.
- Ruff check/format and migration drift checks passed; no new migrations.
- Frontend TypeScript/Vite production build passed.

These are local synthetic checks, not live AWS, PostgreSQL concurrency, browser,
or recovery evidence. The code removes archival rather than bypassing its failures.
