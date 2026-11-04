# OneSmarter Secure Mail — Repository Coding Rules


> Scope update — 2026-11-04: the owner removed antivirus from the product. Uploads undergo file-type/size validation, authorization, encryption and integrity checks; no malware verdict is produced. Historical scanning results below do not describe current functionality. Other release gates remain.






Updated: 2026-10-28. Applies to work in this repository; explicit user instructions and applicable AGENTS.md instructions take precedence.



## Start each task



1. Read applicable AGENTS.md instructions, [PRD.md](PRD.md), [TECH_STACK.md](TECH_STACK.md), [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md), and current [ROADMAP.md](ROADMAP.md).

2. Inspect affected code and the working tree. Preserve unrelated user changes and established public behavior.

3. Distinguish implemented, simulated, proposed, and undecided behavior. Never interpret an unchecked roadmap item as completed or an open decision as approval.

4. Make the smallest reviewable change that satisfies the task. Resolve routine implementation details autonomously; ask about material product/security choices not already answered.



RULES.md is a repository reference, not a guarantee that every coding tool automatically loads it. Link it from the repository entry point and consult it explicitly; do not assume automatic AGENTS.md discovery of this filename.



## Language and code style



- Python 3.12+, type hints, PEP 8, clear names, explicit exceptions, and framework conventions. Use Django/DRF as the proposed backend baseline.

- New application frontend code uses React 19, strict TypeScript, functional components, and semantic HTML. Avoid `any`; use `unknown` plus validation at untrusted boundaries.

- Preserve the current plain JavaScript prototype until an intentional migration. Do not convert unrelated files for style alone.

- Keep business workflows and permission rules out of UI components and thin API handlers. Use focused modules rather than broad abstractions or premature microservices.

- Verify unfamiliar/version-sensitive APIs against installed versions or primary documentation. Never invent cryptographic or provider APIs, package names, or settings.

- Pin approved dependency versions during scaffolding and commit reproducible lockfiles. Do not add overlapping frameworks or libraries without a concrete requirement.



## File structure



Current implementation structure:



```text

secure_mail/                 # framework-independent routing policy

tests/                       # routing tests

backend/config/              # Django settings, URLs, Celery and WSGI

backend/apps/core/           # focused workflow modules in one Django app

  auth.py, accounts.py       # staff MFA and administration

  conversations.py           # messages, grants, OTP, uploads and access

  crypto.py, keyring.py       # owned encryption/key lifecycle using vetted primitives

  key_migration.py           # resumable envelope rewrapping

  storage.py, mail.py         # private storage and email boundaries

  audit.py, services.py       # append-only events, archive, exports and shared transactions

  management/commands/       # bootstrap, development worker and operator key commands

backend/tests/               # integration and cryptographic regression tests

frontend/src/                # React pages, reusable components, transport, styles

frontend/e2e/                # real-browser tests

scripts/                     # local and container initialization

compose.yaml                 # local synthetic PostgreSQL/Redis environment

.github/workflows/           # repeatable backend/frontend checks

web/                         # preserved historical static prototype

```



Keep these focused modules in a modular monolith. Split Django apps only when that improves actual ownership/dependency boundaries. Do not create empty architectural layers.



Preserve `secure_mail.decide_delivery` and its tests unless an intentional change is required. Make it importable through proper project packaging; do not add runtime sys.path hacks. Only create modules needed by the active change. Test locations follow the chosen backend/frontend tooling once configured.



## Product invariants



- Reject invalid submissions before sending. The pure routing function's protected result is not a validation success or authorization grant.

- Apply routing to authenticated sender identity and all To/Cc/Bcc envelope recipients. Exact company domain only. The application requires an explicit Nophi toggle and acknowledgement; subject matching remains only in the historical pure-policy module.

- Secure-information requests and existing protected threads cannot be downgraded through Nophi or internal recipients.

- Nophi requires an explicit staff permission. The backend implements that check; preserve it and its regression tests. Never rely on hiding a button.

- Nophi off means protected portal delivery for every recipient, including internal addresses. Only an authorized, acknowledged Nophi override on a new ordinary message permits ordinary email; workers must reject queued deliveries from the retired internal-only route.

- Blank instructions are valid for secure requests. Recipient responses require text and/or files. Ordinary-message validation must follow the approved product rule.

- Protected traffic uses generic Proton notifications; confidential content stays in the portal. Normal delivery is not synonymous with plaintext transport.

- Direct Proton web/mobile sends are outside current enforcement. Do not claim a gateway, mobile interception, or partner API exists.

- Application-managed staff accounts require MFA. Recipient email OTP is a separate mailbox-verification mechanism.



## Security and data handling



### Administration and immutable audit invariants



- Administrators retain normal scoped staff workflows plus Access → Accounts / Audit logs. Check account-management, privilege-management, usage-read, audit-read and audit-export capabilities on every API, count, query and download; admin role does not confer global content access.

- Provision staff through authorized admins or controlled first-admin bootstrap, not public signup. Default to staff with Nophi off. Field-allowlisted profile updates cannot change role/email/MFA/status implicitly; prevent escalation by granting permissions the actor cannot manage.

- Use hashed, fixed-mailbox, expiring single-use activation invitations. Require password setup and MFA before protected access; never display/email a permanent password selected by an admin. Record last successful login only after complete MFA and separate last activity from background polling.

- Keep account/invitation/MFA/lockout states separate. Make lifecycle/permission changes transactional, protect the last active admin under concurrency, invalidate sessions, recheck queued-send authority, and preserve conversation/audit attribution.

- Implement PRD usage definitions from unique committed business records, not HTTP/SMTP retry counts. Distinguish period counts from current storage gauges, avoid organization-total double counting, and expose freshness/unknown values.

- Audit bodies are append-only: no update/delete/clear-history API or cascade deletion. Corrections append linked events. Database restrictions and protected storage enforce the guarantee; hidden buttons, an ORM override or a hash alone are insufficient.

- Commit business mutations with their required durable audit events; roll back the mutation if its event cannot be recorded. Record denied/failed attempts reliably without secrets or unrestricted request payloads. Audit admins' own actions and user-initiated history reads/exports without recursive logging of the internal writer.

- Protect canonical archive versions for approved retention; preserve exact version references, recovery keys, sequence/manifests and reconciliation. Show pending archival honestly and alert on gaps/failures. Retention and region remain prerequisites for real-data use.

- Exports are scoped to fixed filters/snapshot, redacted, permission-checked at generation/download, time-limited and audited. Neutralize spreadsheet formulas in CSV. Export expiry never deletes canonical audit history.

- Use allowlisted search/sort fields, parameterized queries, stable ID tie-breakers, explicit null ordering, bounded windows/pages and snapshot-safe audit pagination. Build semantic accessible tables with visible sort arrows and correct `aria-sort`; include mobile, no-results, stale-data and permission-loss states.



### General application controls



- Authorize every object operation by organization, conversation, recipient/staff grant, and current lifecycle state; include downloads and uploads. Administrative role alone must not expose content.

- Keep secrets in environment configuration/managed secrets, never source, Dockerfiles, test fixtures, or logs. Use placeholder-only configuration examples and review existing ignore rules before adding them.

- Use ORM-safe operations and parameterized queries; validate inputs server-side; escape output; sanitize any supported rich text through a reviewed policy. Do not render untrusted HTML directly.

- Use Secure/HttpOnly/SameSite cookies, CSRF protections, deliberate CORS, code/token throttling, and consistent non-enumerating errors. No browser-persisted access tokens or decrypted content.

- Hash opaque link tokens and use a keyed verifier for short OTPs. Never log or store raw verification codes as the verification record. Design any encrypted delivery copy with explicit expiry and deletion.

- Sensitive content, raw codes, data keys, tokens, credentials, and confidential filenames/subjects must not enter logs, traces, analytics, queue payloads, or crash reports.

- Use versioned encryption envelopes and trusted authenticated context. No homemade cryptography, plaintext fallback, or hardcoded keys. The previous educational envelope example is not the production crypto implementation.

- Own the key-management implementation. AWS KMS and OSIVault are excluded from the production target by user decision. Follow KEY_MANAGEMENT.md and KEY_SERVICE_ARCHITECTURE.md. Existing KMS adapters/settings and storage/archive SSE-KMS calls are legacy debt to replace safely; do not reintroduce a managed-KMS dependency indirectly. Use reviewed primitives and an independently reviewed exact hybrid protocol, not invented mathematics or an unreviewed combiner presented as standard.

- Implement the isolated key-service boundary: no runtime private/root-key export; scoped authenticated workloads; separate administrative identities; sealed-state fail-closed behavior; controlled root custody/recovery. A local `.env`/root file is not production custody. Root unlock method remains an explicit release decision.

- Preserve versioned envelopes and canonical trusted AAD. Fresh DEK and 96-bit nonce for new content encryption; never repeat a key/nonce pair. Full 128-bit GCM tags must authenticate before plaintext release. Storage retries may resend existing envelopes; new encryption gets fresh randomness. Rewrapping preserves content ciphertext while creating a fresh wrapper. Unknown/malformed suites never downgrade.

- Keep old versions usable for retained documents and backups. Root rotation, organization-key rotation and compromise response are distinct. Interrupted migrations must retain a valid reference; no automatic key destruction based on session expiry. Persistent private keys do not imply forward secrecy; neither hybrid use nor roundtrip tests is independent approval.

- Committed visitor submissions stay on the original thread without automatic age-based deletion. Session timeout, logout, access expiry and revocation end recipient access, not storage or assigned-staff read access. Protect committed objects from orphan cleanup and bucket lifecycle expiry. See DATA_RETENTION.md; detailed disposal/legal-hold, audit/export/backup policy and region remain required before real-data use. Keep development/staging synthetic.



## Database, concurrency, and jobs



- Use PostgreSQL foreign keys, constraints, query-driven indexes, bounded pagination, and explicit transactions. Avoid N+1 access patterns.

- Commit business state with the outbox record. Use staged object finalization and cleanup for storage/database failures.

- Atomically consume OTPs and enforce idempotency with database constraints and transactional logic, not a browser flag or Redis-only check.

- Scope idempotency to the authenticated actor and operation; detect reuse with incompatible payloads. Retrying must not duplicate a logical submission.

- Use bounded retries with backoff, timeouts, attempt tracking, and actionable terminal/uncertain outcomes. SMTP is not an exactly-once channel.

- Jobs carry non-sensitive identifiers and recheck current state where required. Revocation must remain effective even if an older job retries.

- Review migrations for data preservation, deployment order, and recovery. Test important concurrency behavior against PostgreSQL, not just an in-memory substitute.



## Error handling and observability



- Return stable error codes with safe user-facing messages and appropriate HTTP status. Do not expose tracebacks or resource existence to unauthorized callers.

- Separate durable submission success from email-notification status. Report provider accepted, delivered, bounced, failed, or unknown only when supported by evidence.

- Log structured resource references, correlation IDs, event type, outcome, timing, and policy reason where approved. Redact request paths containing invitation tokens at proxy and application layers.

- Fail closed on key/integrity/authorization failures. Do not retry invalid credentials indefinitely or convert protected traffic into ordinary content delivery after an outage.

- Make queue, mail and key-service health actionable without displaying credentials. Define alert ownership as part of operational readiness.



## Frontend implementation



- Follow DESIGN_SYSTEM.md tokens and wording. Keep API/validation logic separate from presentation.

- Include loading, error, empty, expired/revoked, and partial-upload states. Abort stale requests and clear sensitive state when access ends.

- Use accessible labels, focus management, keyboard interaction, and responsive layouts. Avoid unnecessary state, re-renders, and decorative dependencies.

- Do not expose Bcc identities in DOM or API responses to unauthorized viewers. Client-side filtering is not authorization.

- Do not infer security from icons or badges. Keep demonstrations visibly labeled and isolated from production flows.



## Verification



Existing runnable check from the repository root:



```bash

python -m unittest discover -s tests -v

```





For administration, test staff/direct-route/API denial, organization-scoped counts/exports, invitation duplicates/reuse, post-MFA timestamps, suspended sessions/pending sends, stale permissions, last-admin concurrency, metric deduplication and stable search/sort/pagination. Audit tests must prove mutation/cascade deletion denial, linked corrections, actual protected-version retention, gap/outage visibility, projection rebuild and export redaction/escaping/download reauthorization. Run destructive storage checks only against dedicated synthetic test resources under the approved test plan.



Run the checks appropriate to the actual change. Add backend/frontend/CI scripts when those components exist; do not report unavailable tests as passing. Documentation-only changes need consistency/link/diff checks, not artificial tests mirroring prose. UI changes need keyboard/mobile review and real workflow validation when the backend is available.



Use synthetic accounts/documents in tests. Mock transports at unit level and use dedicated test mailboxes for integration evidence. Report test scope and remaining limitations accurately.



## Git and documentation workflow



- Inspect `git status` and applicable branch guidance before editing. Do not reset, overwrite, or commit unrelated user work.

- Prefer small focused commits when a commit is requested. Proposed message convention: `docs:`, `feat:`, `fix:`, `test:`, `refactor:`, `chore:` followed by the concrete change; this is not an existing enforced hook.

- Do not push, merge, or deploy merely because a documentation task requests files. Follow the user's authorized scope.

- PR descriptions lead with the problem and resulting behavior, list relevant verification, and state material limitations. Never include secrets or confidential samples.

- Update the owning document when product/architecture decisions change. Update ROADMAP.md with dated evidence, not optimistic percentages or invented completion dates.

- Preserve a distinction between prototype behavior, implemented code, tested integration, and production approval. No tests or planning documents imply security certification.



## Custodian-page implementation rules



Keep the custodian login independent of document-key availability, with explicit dedicated identity and mTLS plus password. No implicit grant through the staff-admin role. Never store recovery inputs in browser storage, logs, environment variables or application databases. Preserve restart-sealed behavior and fail closed when the service is unavailable. Root operations require session, CSRF, exact Origin and custodian role; import/rotation requires maintenance scope. Keep reference cryptography dependencies test-only and the production gate intact. See KEY_SERVICE_OPERATIONS.md.

