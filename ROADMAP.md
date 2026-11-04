# OneSmarter Secure Mail — Progress and Roadmap

> Audit storage decision — 2026-11-04: staff/admin activity logs remain in the same
> application PostgreSQL database on EC2. External audit archival code is removed; no audit bucket or second automatic
> audit copy is required. Earlier mandatory S3/Object Lock audit requirements are
> superseded. Database logs are not immutable against privileged administrators.
> Key-service security journals, recovery snapshots and cryptographic release
> gates remain separate and unchanged. See [DATABASE_AUDIT.md](DATABASE_AUDIT.md).



> Scope update — 2026-11-04: the owner removed antivirus from the product. Uploads undergo file-type/size validation, authorization, encryption and integrity checks; no malware verdict is produced. Historical scanning results below do not describe current functionality. Other release gates remain.





Updated: 2026-10-28. This records observed implementation and remaining work; it is not production approval.



## Current position



The repository now contains a functioning Django/React application, not just the original static prototype. The staff-to-recipient document flow, MFA, administrator accounts, searchable audit history and OneSmarter-owned cryptographic system are implemented and locally exercised. Real confidential data remains prohibited until the release gates are satisfied.



The user replaced the proposed OSIVault dependency with our own system on 28 October. The application has no OSIVault runtime requirement. We own envelope formats and key lifecycle while using established Cryptography/OpenSSL primitives. See [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md).



**Self-managed key service update (28 October):** AWS KMS/OSIVault runtime protectors are removed. A separate HTTPS/mTLS service, operator-unseal webpage, scoped identities, version/root rotation, encrypted backup and local-key import are implemented for synthetic use. S3 document/archive adapters use SSE-S3 plus application encryption. Production review, full PQ transport validation, external audit anchoring and operational approval remain open. See [KEY_SERVICE_OPERATIONS.md](KEY_SERVICE_OPERATIONS.md).



## Implemented and checked locally



| Area | Delivered behavior | Evidence / limitation |

| --- | --- | --- |

| Backend and frontend | Django 5.2/DRF; React 19/strict TypeScript/Vite; pinned lockfiles | Django checks, migrations, Ruff and frontend build/format checks |

| Staff authentication | Passwords, TOTP MFA, enrollment QR, single-use recovery codes, post-MFA last login, recent-MFA recheck | Backend tests and actual browser enrollment/login |

| Staff management | Admin-created accounts, invitation activation, roles/permissions, suspend/reactivate/deactivate, recovery and session revocation | API tests; account creation/search/sort exercised in browser |

| Last administrator safety | Last active administrator and last privilege manager protected | Transactional checks and regression tests; PostgreSQL concurrent races still require validation |

| Routing | Exact internal domain, To/Cc/Bcc, protected requests/threads, explicit Nophi permission | Original seven policy tests plus API tests |

| Protected conversations | Optional instructions, encrypted content, private recipient replies, expiry/revocation, own-conversation scope | API tests and browser request/reply flow |

| Recipient access | Fixed destination, masked mailbox, opaque tokens, throttled single-use codes, scoped sessions | Positive/negative tests; separate browser context verified |

| Documents | Actual uploaded bytes, encrypted private storage, authenticated downloads, type/size limits | Browser download compared byte for byte with original; crypto/context tampering tests |

| OneSmarter encryption | Real ML-KEM-768 + X25519 hybrid DEK wrapping; AES-256-GCM content; tenant key versions | Algorithm roundtrip/tampering/downgrade/isolation tests; independent protocol review pending |

| Rotation and recovery | Old versions retained; bounded rewrap; old documents remain readable without content re-encryption | Record/file migration, ciphertext preservation, failed-rotation and root-loss/recovery tests |

| Self-managed key custody | Separate HTTPS service and custodian webpage; restart sealed; no runtime private-key export | Local HTTPS, encrypted restore, concurrent rotation/read and browser flow tested; production approval pending |

| Delivery | Durable encrypted outbox, local capture, SMTP adapter, explicit retry, stale-code/invitation and permission checks | Local worker/browser tests; real Proton integration unconfigured |

| Audit | Append-only database triggers, immutable event API, stable signed snapshots, filters/sorts/details, expiring CSV export authorization | Mutation-denial, stable snapshot and formula-escaping tests; browser audit search/details |

| Archive | S3 COMPLIANCE Object Lock writer with version/retention confirmation | Adapter implemented; live enforcement, verification/rebuild drill still required |

| Interface | Teal/navy reference, responsive staff/recipient views, accessible forms/dialogs, mobile sign-out | Desktop/mobile screenshots inspected; browser reflow/error check |

| Infrastructure | Local PostgreSQL/Redis/API/worker/beat/frontend Compose; GitHub Actions checks | Supplied; Docker absent locally and remote CI not run in this session |



## Verification record



- Backend suite: **52 tests passed** on 2026-10-28, including retained-document access after recipient revocation.

- Real-browser integration: one full scenario passed with the OneSmarter hybrid encryption module, covering request, OTP, upload/reply, exact-byte download, account creation, audit search/details and mobile reflow.

- Frontend: strict TypeScript/Vite production build passed; Prettier checks passed; npm dependency install audit reported zero vulnerabilities.

- Local API/database tests used SQLite, not PostgreSQL. KMS used a test double. Delivery used local capture. These results do not imply external integration certification.

- Browser screenshots and private test fixture state are in ignored `.runtime/browser-artifacts/`. The normal `.runtime/dev.sqlite3` workspace remains separate from the browser-test database.

- Documentation reconciliation on 2026-10-28: all 12 top-level Markdown files passed local-link, code-fence and encoding checks; `git diff --check` passed. The existing retained-file-after-recipient-revocation regression was rerun in an isolated temporary test directory: **1 passed**. This is not a new full-suite run or evidence that session/access-expiry and recovery cases all pass.



## Remaining production gates



1. Independent review of our exact hybrid protocol, key custody, legacy migration and dependency provenance; independent test vectors and complete PQ path coverage.

2. Approve region, exceptional disposal/legal hold, audit/export/backup policies and availability targets. Committed submissions have no automatic timed deletion; prove retention independently of sessions/access expiry.

3. Independently review and harden the implemented isolated service and operator-unseal custody. Validate explicit migration and deployed SSE-S3 policies. Provision private storage/compute/network identities and perform actual root/key-store/data recovery drills without AWS KMS.

4. PostgreSQL concurrency tests for duplicate requests, code consumption, account/permission races, audit sequencing and worker contention; remote CI execution.

5. Live Proton SMTP transport verification, sender configuration, monitoring/bounce handling and delivery uncertainty tests.

6. Real ClamAV deployment/signature maintenance, isolation, quarantine/outage tests, cleanup/reconciliation and safe upload lifecycle review.

7. S3 immutable-version denial tests, protected pending-journal/outage policy, archive-gap detection and projection rebuild verification.

8. Independent security and accessibility review, deployment/restore/rollback drills and operational ownership.



The detailed acceptance criteria remain in [PRD.md](PRD.md), [TECH_STACK.md](TECH_STACK.md), and [RELEASE_GATES.md](RELEASE_GATES.md). Shared conversation ownership/reassignment, exceptional administrative document access, account date-range filters, audit new-event indicators and asynchronous large exports are not represented as implemented features.



## Next encryption delivery sequence



1. Decide operator-unlock versus hardware custody and recovery/availability policy; freeze the exact hybrid profile and internal operation schemas with independent review.

2. Build isolated scoped wrapping service, sealed-state behavior and separately protected audit records; integrate without returning persistent private keys to Django.

3. Inventory and migrate legacy-protected records; replace KMS root/storage/archive paths and configuration; retain only explicitly supported version compatibility.

4. Add independent vectors/interoperability, sealed/unavailable service, authorization, concurrent migration/rotation, actual recovery and verified transport tests.

5. Validate retained-file lifetime independently of session/grant expiration and cleanup, then complete deployment/review gates. No production enablement is implied by documentation updates.



## Session history



| Date | Change | Evidence |

| --- | --- | --- |

| 2026-10-27 | Created project guidance from the supplied requirements/HTML and recorded user decisions | PRD, stack, design, coding rules and initial roadmap |

| 2026-10-27 | Added administrator-managed accounts and immutable audit requirements | Access workspace and lifecycle/usage/table/archive contracts |

| 2026-10-27–28 | Built the Django/React application, local workers, tests and container/CI definitions | Running local services and end-to-end browser flow |

| 2026-10-28 | Replaced the proposed OSIVault dependency with OneSmarter-owned encryption and key lifecycle | Real ML-KEM hybrid envelopes, rotation, resumable migration, recovery/tamper tests and updated guides |

| 2026-10-28 | Superseded AWS KMS with a self-managed key-service target; documented AES/hybrid/PQ requirements and persistent same-thread visitor submissions | Documentation and code-path inspection only; runtime adapters unchanged; new key service/custody and expanded tests pending |



No production release, external deployment, Git commit, push or pull request has been made during this implementation.



## Key-service delivery verification — 28 October 2026



Follow-up: consolidated local/service hybrid encryption into a shared protocol without changing valid v2 envelopes. Added strict JSON/version rejection, fresh-material checks and Django sealed-service read/write/rewrap denial with recovery. Required PQ network coverage and independent protocol approval remain separate release gates.



73 backend/policy tests passed; the opt-in custodian browser test passed separately. Ruff and Django/migration checks passed. Delivered independent maintenance sign-in, Unseal/Seal, root rotation, scoped mTLS runtime APIs, explicit local import and encrypted backup recovery. No live deployment, production custody ceremony, independent protocol review or full PQ transport validation is claimed.



## Application-instance document storage - 28 October 2026



User selected persistent storage on the AWS application instance for uploads, superseding primary S3 attachment storage. Updated PRD, stack, retention and release gates. Dedicated EBS data volume is the proposed implementation; region, backup destination and no-KMS-compatible volume encryption remain open. No deployment changes made. Audit archival and custody isolation remain separate requirements.



## Audit, scanning, operations and accessibility follow-up



Added archive exact-version readback verification, a protected-manifest workflow and independent recovery projection, strict ClamAV response handling and outage/rejection tests, a real-scanner Compose/CI configuration, operational probes and dry-run-first staged cleanup. Seven isolated PostgreSQL 17 tests passed, including concurrency and a real dump/restore drill. Browser flow with axe and keyboard checks passed after fixing avatar contrast and modal focus return. Full production AWS/ClamAV deployment, independent audit checkpoints, actual alert routing and manual accessibility review remain pending. Private Email supersedes Proton for the saved local SMTP profile; no live message was sent. See OPERATIONS_RUNBOOK.md.



## Portal separation and deployment interface - 2026-10-28



Staff and administrators require exact @onesmarter.com accounts. Recipients may use any valid mailbox. Staff enter through /staff/; invitation links enter through /recipient/ and use a separate API namespace and session cookie. Normal user pages no longer display development banners, test-mailbox controls or engineering release requirements. Operator test tools require explicit opt-in. Local captured notifications are explicitly marked not emailed. This supersedes earlier instructions to show development-mode banners on customer pages; deployment status remains documented and enforced on the server. See [DEPLOYMENT.md](DEPLOYMENT.md) for compatibility, configuration and outstanding release blockers.



Portal-boundary verification (2026-10-28): full regression run 125 passed, 12 opt-in tests skipped; final focused boundary tests 7 passed after disabling legacy recipient endpoints by default. Actual browser staff request/recipient upload/staff read/admin audit workflow passed with accessibility checks. TypeScript/build, formatting, Ruff and Django checks passed. Local API was restarted; recipient entry point responds and test-mailbox/legacy recipient endpoints return 404. No public production deployment or real email was verified.



## Connections and SMTP verification - 2026-10-28



Completed Connections screen with explanatory service cards, own-account delivery counts, sender-management permission links, refresh and a rate-limited live scanner health check. Backend tests verify account isolation, secret redaction, failed health checks and no email side effects. 35 focused tests passed; full staff/recipient browser flow plus desktop/mobile Connections and accessibility checks passed. Frontend build/format and Ruff lint/Django checks passed. Global Ruff format found a separately added scripts/start_local_maintenance.py formatting issue; this unrelated file was left unchanged.



The user authorized enabling the saved Private Email SMTP profile and resending one captured notification. SMTP authentication succeeded and that notification reached provider_accepted. The running API/worker now use SMTP; previous captured notifications were not bulk-replayed. Inbox receipt is not confirmed, and localhost invitation links still require this computer.



## 29 October 2026 — specification governance and crypto ownership



Retired handoff v1.0 through the repository v1.1 notice; PRD is the product source

of truth. Production and real-PHI use remain blocked. External review funding,

named reviewer, detailed P1-1/P1-2/P1-3 reports, remediation/retest and security

approval are pending. No external review was commissioned by this change.



## 29 October 2026 — P1 remediation



Implemented mandatory origin-MAC wrappers, pre-activation key snapshots and a

verified restore CLI; explicit off-host-input initialization with synthetic-only

local-secret exceptions; owner-preserving deactivation enforcement; recipient idle

activity and memory-only draft retention; explicit Nophi consent/expected-route

checks; upload progress and backend-driven Connections facts. Full tests: 181

passed, 13 skipped; focused P1 checks: 6 passed. Existing runtime crypto was not

restarted or migrated. Legacy authenticity migration, trusted rollback detection,

real off-host recovery, quorum/HSM custody and independent approval remain open.





## P2 remediation update (2026-10-29)



See [P2_REMEDIATION.md](P2_REMEDIATION.md) for capability configuration, required idempotency headers, administrator MFA reset, staged quotas, evidence and limitations. P2-10 remains partial: metadata caching does not remove all remote crypto calls from transaction locks. Production approval and trusted legacy-envelope migration remain blocked.





## P3 hardening update



See [P3_REMEDIATION.md](P3_REMEDIATION.md) for stable rotation IDs/expected versions, recipient URL cleanup, bounded encrypted-subject search, and deployment verification limits. Rotation retries must reuse the original operation parameters.





## 29 October v2 review follow-up



See [V2_REMEDIATION.md](V2_REMEDIATION.md) for per-finding source status, tests and rollout requirements. Code remediation does not close independent review, provider password rotation, off-host custody, external rollback anchoring or deployment evidence. N-17 remains partial because full audit-history snapshots still hold the key-store lock and post-commit publication crashes need reconciliation. Production remains blocked.



## Organisation SMTP and secure conversation threads (31 October 2026)



This replaces the earlier shared Proton/Private Email sender configuration and the earlier separate-copy rule for To/Cc recipients.



- Administrators configure the organisation SMTP hostname, verified TLS submission mode (STARTTLS/587 or TLS/465), enabled state, and sender display name in Connections. Staff save their own approved SMTP email and password there. From and Reply-To use that same staff email; the application never falls back to a shared provider credential. The chosen local transport is smtp.ionos.com:587 with STARTTLS and display name OneSmarter Support. Real authentication requires each staff member's provider-supported credential; it has not been verified by automated tests.

- SMTP passwords are encrypted using the existing document encryption/key-service boundary, bound to organisation and staff identity. They are write-only in APIs, excluded from audits, and included in key migration. Admin transport changes require staff to re-enter credentials before sending to the changed destination. SMTP connections reject private/reserved network destinations and verify TLS certificates.

- Single-recipient protected sends continue the existing owner-recipient chat. Multiple visible To/Cc recipients share a separate thread, reused for the same owner and visible participant set. Each BCC recipient receives a private copy in their own chat. BCC identities are never returned to other recipients. Adding/removing visible participants starts a different group thread; it does not reveal old group history.

- Messages display author, date, and expandable From/To/Cc details. A BCC viewer sees only their own BCC status; the owning staff can see the BCC metadata on their original sent message. Reply to sender is private to that message's author. Reply all reaches the owning staff and visible To/Cc participants; BCC copies cannot Reply all. Private recipient-to-recipient replies are hidden from other participants, including staff, by API and attachment authorization.

- Notifications contain a generic secure-message notice and portal button, never the confidential subject/body/files. The recipient verifies their own mailbox using OTP. Recipient portal replies notify the staff owner when the owner is a recipient of that reply. Ordinary incoming email is not imported; notifications instruct recipients to reply in the portal.

- Existing ciphertext and conversation identifiers are preserved. Historical group threads are not merged or reparented. New direct-chat mappings can adopt eligible existing private threads; unauthenticated legacy ciphertext remains subject to the existing migration gate.

- Nophi remains a separately authorized ordinary-email option. These group-thread and private-copy rules apply to protected portal traffic.



Verification for this change: 95 focused backend tests passed; 19 Playwright browser tests passed across SMTP setup, shared message details/reply selection, draft refresh and downloads. TypeScript/Vite build, Ruff check and migration drift check passed. Local additive migration 0015 applied after a SQLite backup; API and staff portal both returned HTTP 200. Browser API fixtures verify interface behavior, while Django tests enforce authorization. Actual provider SMTP delivery, production PostgreSQL group concurrency and production deployment are not established by these checks.



## Local evidence preservation and OTP sender update — 31 October 2026



See [EVIDENCE_ARCHIVE.md](EVIDENCE_ARCHIVE.md) for the implemented capture catalog, original-file hashes, server-download provenance, encrypted create-only local bundles, verified exports, legacy backfill and optional RFC 3161 verification. The user selected local preservation for now and an unset TSA. Deployment must not silently switch to AWS. Local preservation is not administrator-proof cloud WORM; pending timestamps are not trusted timestamps. Hospital-list reconciliation is excluded.



Emailed recipient OTP challenges authenticate through the organisation SMTP transport using the conversation owner's encrypted staff SMTP username and password. Only the From/envelope sender is support@onesmarter.com; Reply-To remains the staff address. No separate support password is required. The provider must authorize each staff account to send as support@onesmarter.com; rejected delivery fails closed without a sender fallback. Missing staff credentials block OTP delivery. Staff authenticator TOTP is unchanged. Ordinary conversation notifications retain each owning staff member's SMTP sender.



Local key-service calls now prefer the IPv4 loopback listener while retaining localhost certificate verification and PQ requirements. Every wrap/unwrap still contacts the service; no plaintext, data keys or readiness result is cached to achieve the speedup. Initial workspace session checks time out after eight seconds with retry; authenticated drafts survive transient polling failures.



Observed verification, 31 October 2026: archive/OTP/key-service regression run 112 passed, 1 opt-in browser test skipped; final catalog/SMTP follow-up 39 passed. Browser regression set had 24 passes and one wrong button-label expectation; correcting the expectation to the actual initial-session retry button produced 2/2 evidence/timeout passes. TypeScript/Vite build, Ruff and Django checks passed. The original local key-service status call took 2.05–2.10 seconds; IPv4-preferred localhost calls retained certificate/PQ checks and measured 14–20 ms. Local portal session probes measured 16–17 ms, readiness 38–47 ms. Two existing encrypted evidence bundles were verified live. Three historical unauthenticated envelopes remain unreadable and untouched. Support OTP credentials and live TSA remain unconfigured; no external email or TSA request was sent for this work.





## Required capture provenance — 31 October 2026



New uploaded files require both a source document HTTPS URL and an original download timestamp with timezone. Missing, invalid, timezone-free or future download times are rejected before staging. The shared staff/recipient upload form collects one file at a time with its own provenance. These values remain uploader-declared, not independently verified. Direct URL capture records the requested/final URL and actual server download-completion time automatically. Finalization also rejects older staged files missing these fields; upload them again with accurate provenance. Existing committed captures and explicit legacy backfills remain unchanged and honestly report unknown fields. No earlier download time is inferred from file modification time or portal upload time. Files with no known web source cannot be newly captured through this workflow; do not invent a URL or time. TSA verification and local-storage limitations are unchanged.





## Compact portal design — 31 October 2026



Refined the shared design across staff and recipient pages: stable desktop sidebar, tighter cards and tables, responsive expiry controls, accurate breadcrumbs, accessible selected navigation/filter states, clearer filtered empty states, expandable connection diagnostics and attachment provenance. SMTP password storage remains encrypted with remote key custody; closed SMTP connections release the password reference. Browser review covers eight staff screens plus sign-in and recipient entry at 1440 and 360 px, with automated accessibility scans on desktop. UI fixtures are synthetic; these checks do not establish live SMTP delivery or a production security certification.





## Recipient access policy update — 2026-10-31



This supersedes earlier 1/7/30-day conversation/link expiry requirements. Recipient invitation links do not expire automatically. Existing conversation deadlines are retained only as historical data and are not enforced. New conversation records use a null deadline. Continued direct/group chats preserve old invitation token hashes; new messages do not invalidate existing stored links. All links require mailbox OTP verification and remain subject to grant/conversation revocation and active-owner checks. OTP expiry, recipient idle timeout and absolute session lifetime remain enforced. The compose expiry selector is removed; access details say Until revoked. Older clients may send expiry_days for compatibility, but it does not impose a deadline. Previously deleted token hashes cannot be reconstructed; those recipients need an available invitation.





## Recipient reply routing update — 2026-10-31



Recipient private replies always go to the assigned staff owner, even when the selected message was authored by another recipient. They are visible only to that replying recipient and the owner, including attachments; the owner receives a notification. Reply all remains shared with eligible To/Cc recipients and visible to the owner. BCC private copies cannot reply all. Staff can still reply privately to a recipient. Historical recipient-to-recipient private messages are now visible to the assigned owner for review; administrator status alone does not grant content access. Submission audit metadata records reply mode and whether a recipient reply is private to the owner. This supersedes earlier recipient-to-recipient private reply behavior.

