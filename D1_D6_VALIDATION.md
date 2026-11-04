# D1–D6 candidate validation — 2026-11-04

Candidate — internal design decision 2026-11-04, independent review pending.

The supplied decision record is saved verbatim in
DESIGN_DECISIONS_2026-11-04.md. This is an uncommitted working-tree evaluation,
not an immutable-commit review, GitHub CI result or production approval.

## Changes under evaluation

- RP-04/RP-05: root-wrapped HMAC audit keys, Ed25519 checkpoints with explicit
  sig_alg, authenticated protected-state commitments and external freshness checks.
- D3: custodian-session/CSRF-protected outage overrides with a typed reason,
  MACed exception event, unverified status and export alert. Document admission
  is disabled while unverified. Corruption cannot be treated as an outage.
- D4/D5: test-only local receiver and S3 COMPLIANCE/SSE-S3 adapter, separate
  profile/account configuration, conditional immutable successors, exact-version
  retention validation and no automatic checkpoint deletion.
- D6: current-DEK guard for mutable SMTP credentials and MFA only. Authentic
  stale ciphertext and ledger/state rollback rejection are regression-tested.
- Item 9: local restore alone retains old-root snapshots; retirement needs
  separately signed remote-copy and clean-machine restore evidence.
- Complete v2 envelope vectors use fixed public synthetic inputs; separate
  primitive libraries verify them locally. Independent-team verification is open.

## Evidence

| Check | Result / evidence |
| --- | --- |
| Collected backend suite, Python 3.12 / SQLite | **548 passed, 18 skipped**, 202.46 seconds; `.runtime/d1-d6-full-4.log`, exit 0 |
| Candidate, mutable-field, recovery, S3 and checkpoint transport suite on actual hybrid runtime | **62 passed**, `.runtime/d1-d6-pq-1.log`; Python 3.15 / OpenSSL 3.5.9, RUN_PQ_TRANSPORT=1 |
| Ruff check backend/scripts | Passed |
| Ruff format check | Full backend/scripts passed before concurrent portal edits; final candidate/recovery/test scope passed (21 files). Repeat the global check on the frozen commit. |
| Custodian portal JavaScript syntax | `node --check backend/keyservice/portal.js` passed |
| Root routing/dependency-hash tests | **13 passed** (`python -m pytest tests -q`) |
| Current revision GitHub CI | Pending; earlier CI evidence applies only to its recorded commit |
| Live AWS, PostgreSQL, browser visual/accessibility and production drills for these changes | Not run |

The full runs found nondeterministic pre-existing OTP and invite-history tests: two jobs can
have identical created_at values, so ordering by time could select the invitation.
The tests now select each separately created job explicitly and still require
the five-attempt lockout, correct-code rejection after lockout, distinct reply
links, old-link validity and revocation behavior. No
authentication rule or security assertion was weakened.

Reproduction uses APP_ENV=test, DJANGO_READ_DOT_ENV=false,
MAIL_PROVIDER=development and an isolated pytest --basetemp directory. The hybrid
run additionally sets RUN_PQ_TRANSPORT=1 and uses the provisioned hybrid runtime.
No real email, credentials, cloud provisioning or live-store changes occurred.

Unrelated portal implementation/tests changed concurrently during this run.
The collected suite is evidence for what it loaded, not subsequent edits to
those files. Candidate source hashes are retained in
`.runtime/d1-d6-source-manifest.json`; freeze the complete tree and rerun CI before
merge. No unrelated semantic changes were made to accommodate this work.

## Open boundaries

F-07 has not started: D7 requires the prerequisite changes to be merged and tested.
Item 13 remains open. See REVIEW_HANDOFF_2026-11-04.md for owner/reviewer and
deployment work. Ed25519 is classical; S3 SDK transport has no verified PQ claim.
Valid unexported tails, explicit outage freshness overrides and untrusted sealed
observations retain the documented residual risks. Production startup is blocked.
