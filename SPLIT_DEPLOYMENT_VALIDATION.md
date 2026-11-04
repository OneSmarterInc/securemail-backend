# Split repository validation — 2026-11-04

Source: current local OneSmarter Secure Mail implementation, exported without
private environments, runtime stores, credentials, documents or virtual environments.
Destination publication uses GitHub CLI account `ammar-1109`, branch `main`.

- Standalone backend: **563 passed, 15 skipped**, Windows/Python 3.12, isolated
  synthetic SQLite data and captured mail. Skipped tests are not deployment evidence.
- Ruff check and formatting: passed; Django migration drift check: passed.
- Exact-origin CORS, credentialed API requests and required CSRF: seven focused
  tests included in the full run. Unapproved origins do not get CORS authorization.
- Antivirus removed from code, active requirements, upload status fields, UI,
  deployment dependencies and CI antivirus jobs by explicit owner instruction.
  File-type/size validation and sealed-service admission tests remain. Migration
  `0025_remove_antivirus_metadata` removes obsolete attachment metadata; historical
  migrations/audit events remain intact. There is no malware-clean verdict.
- Frontend standalone install/build/format: passed; npm audit found zero known
  vulnerabilities in the installed dependency set. Build tested with
  `VITE_BACKEND_URL=https://securemailbackend.onesmarter.com`.
- Frontend CI [passed](https://github.com/OneSmarterInc/securemail-frontend/actions/runs/41816778244)
  at `31f4628baaf68f07725c261b49fe25e1605c7d81`.
- Both staged publication trees scanned with Gitleaks. Backend exceptions are
  narrowly scoped in `.gitleaks.toml` to reviewed public deterministic KAT outputs
  and two ORM enum/null expressions; no production credentials were allowed.
- Backend CI: pending at initial publication. Existing backend/PQ/hash/container
  security jobs remain; monorepo frontend/browser jobs are excluded from this
  standalone workflow. Paired browser journeys require both repositories and an
  isolated API; this change does not claim a complete deployed browser journey.

Not performed: AWS provisioning, Vercel project activation, DNS changes, real-domain
TLS/PQ verification, production migrations, external crypto review, production
recovery drills or real-data testing. Production startup blocks remain intact.
The proposed frontend domain still requires owner confirmation.
