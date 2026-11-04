# F-11 and RP-05 status — 2026-11-04

## F-11: implemented locally

`backend/keyservice/__main__.py` rejects either `serve` escape flag unless
`APP_ENV` is exactly `development` or `test` and `SYNTHETIC_MODE=true`.
The check precedes key-store access, certificate loading and listener creation.
Allowed exceptions emit a flushed warning to stderr naming the enabled flags.
The existing loopback-only bind restriction for HTTP origins remains enforced.
Private-key import already checks these two environment conditions plus
`KEY_SERVICE_ALLOW_SYNTHETIC_IMPORT=true`; that restriction remains unchanged.

For an explicitly synthetic local maintenance launch, set both environment
variables in the launching process before running `scripts/start_local_maintenance.py`.
The launcher does not silently change a production or missing environment into
development mode. No environment files or live services were changed.

Focused verification: **24 tests passed**, including real CLI subprocess rejection
for production, unset, staging and invalid-case environments, both flags, missing
or false synthetic opt-in, and startup warnings for allowed combinations.
Ruff lint and formatting checks passed for the two changed Python files.

The combined F-11 and existing key-service suite passed with **46 passed,
2 skipped** in 39.33 seconds using isolated test settings and permitted local TLS
listeners. Earlier attempts encountered sandbox socket restrictions and inherited
local-profile settings; disabling `.env` loading for this test process resolved
the configuration interference. No application security defaults were weakened.

```powershell
$env:APP_ENV='test'
$env:DJANGO_READ_DOT_ENV='false'
$env:SYNTHETIC_MODE='true'
.venv\Scripts\python.exe -m pytest backend/tests/test_f11_escape_flags.py -q
```

This is local evidence, not a new full CI or production verification.

## RP-05 / RP-04: unapproved candidate implementation

The subsequently supplied reference explicitly corrects the approval status:
**CANDIDATE — NOT APPROVED**, with implementation authorized only behind a
candidate flag. See [AUDIT_CANDIDATE.md](AUDIT_CANDIDATE.md) for the implemented
wire format, custody, migration, outage behavior and unresolved decisions.

`test_rp05_coherent_audit_rewrite_is_detected` and
`test_rp04_restore_of_older_snapshot_is_detected` pass for candidate stores.
The legacy v1 store has not been silently migrated or represented as repaired.
The candidate detects rollback behind an acknowledged checkpoint, not loss of
every unexported row. Sealed observations remain explicitly untrusted.

Initial local candidate/transport/F-11/legacy checkpoint batch: 64 passed,
1 skipped (actual PQ test needs the hybrid runtime). A separate Python 3.15 /
OpenSSL 3.5.9 run passed all 26 then-current candidate and transport tests,
including actual PQ/mTLS receiver GET/PUT and rejection of a CA-signed identity
absent from its allowlist. Logs: `.runtime/candidate-tests-2.log` and
`.runtime/candidate-pq-tests-1.log`. Later expanded-suite evidence is recorded
in AUDIT_CANDIDATE.md.

Final expanded evidence: **534 passed, 18 skipped** in the full local suite;
**77 passed** in the final related suite on the actual hybrid TLS runtime,
including state-splice and interrupted migration/root-rotation regressions.
See `.runtime/rp04-rp05-final-regression.log` and
`.runtime/candidate-final-state-hybrid.log`.

No live store, service, custody secret, receiver deployment or production
configuration was changed. No external reviewer has signed off.


## 4 November internal design update

Candidate — internal design decision 2026-11-04, independent review pending.
D1–D6 and current evidence: [design record](DESIGN_DECISIONS_2026-11-04.md),
[validation](D1_D6_VALIDATION.md), [handoff](REVIEW_HANDOFF_2026-11-04.md).
Earlier test counts and CI results apply only to their earlier revisions.
Production remains blocked; F-07 waits for the prerequisite merge and tests.
