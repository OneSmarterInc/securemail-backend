# Repository engineering instructions

Read PRD.md, TECH_STACK.md, RULES.md, ROADMAP.md and the applicable architecture
documents before changes. Follow DESIGN_DECISIONS_2026-11-04.md for the audit
candidate. Match the existing Django/Python and React/strict TypeScript structure.

- Preserve the production startup block and synthetic-only warnings. Internal AI
  decisions and passing tests never count as independent cryptographic approval.
- Keep security changes small and reviewable. Do not change cryptographic suites,
  migration behavior or custody assumptions implicitly. F-07 is a separate change
  only after RP-04, RP-05 and item 10 are merged and tested.
- Never read secrets into reports or commit environment files, credentials,
  runtime databases, recovery secrets or private keys. Use placeholder examples.
- Preserve authentication, authorization, CSRF, strict parsing, scoped rate limits,
  idempotency and fail-closed handling. Log identifiers and error codes, not content.
- Test important rejection and recovery paths, not only successful round trips.
  Use fictional data, isolated temporary directories and development mail capture.
- For backend verification set APP_ENV=test, DJANGO_READ_DOT_ENV=false and
  MAIL_PROVIDER=development. Run pytest, ruff check backend scripts, and
  ruff format --check backend scripts. Use the actual hybrid TLS runtime for
  opt-in PQ tests; skips are not transport evidence.
- Distinguish local tests, CI at an immutable commit, independent review and live
  deployment evidence. Update the evidence documents without inventing counts.
- Do not send mail, provision cloud resources or alter live stores as a side
  effect of tests. Local checkpoint fixtures are test-only.
