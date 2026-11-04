# Production release gates

> Audit storage decision — 2026-11-04: staff/admin activity logs remain in the same
> application PostgreSQL database on EC2. External audit archival code is removed; no audit bucket or second automatic
> audit copy is required. Earlier mandatory S3/Object Lock audit requirements are
> superseded. Database logs are not immutable against privileged administrators.
> Key-service security journals, recovery snapshots and cryptographic release
> gates remain separate and unchanged. See [DATABASE_AUDIT.md](DATABASE_AUDIT.md).


Runtime update (2026-11-04): blanket Django/key-service production startup refusals were replaced by strict configuration validation at the owner's request. See PRODUCTION_STARTUP.md. This does not complete any independent review or deployed evidence gate below. Experimental audit/checkpoint code remains synthetic-only.


> Scope update — 2026-11-04: the owner removed antivirus from the product. Uploads undergo file-type/size validation, authorization, encryption and integrity checks; no malware verdict is produced. Historical scanning results below do not describe current functionality. Other release gates remain.

2026-11-04 addendum: [SECURITY_VALIDATION.md](SECURITY_VALIDATION.md) records current synthetic acceptance checks, external audit-checkpoint support and remaining operational/independent approvals. The production startup block remains. A checkpoint protects an audit-history prefix, not every database row or events after its position.



Updated 2026-10-28. This repository provides a functioning synthetic development application. It must not handle real confidential documents yet. `APP_ENV` values other than `development` and `test` deliberately fail startup. Do not remove that gate simply to deploy.



Internal review on 2026-10-28 reproduced four code defects, subsequently repaired: legacy local-key reads in service mode, sealing limited to one store instance, unbounded version-history responses, and missing audit-chain verification on unseal. See [ENCRYPTION_REVIEW.md](ENCRYPTION_REVIEW.md) for repairs and regression evidence. Independent cryptographic review, external audit checkpoints/rollback detection, approved PQ transport and deployment evidence remain required; passing tests are not release approval.



| Gate | Required evidence | Current position |

| --- | --- | --- |

| OneSmarter-owned cryptographic system | Independent review of the exact hybrid profile, hierarchy, dependency provenance, known-answer vectors and independent interoperability; safe algorithm rejection and migration | Local candidate implemented; not independently reviewed and not X-Wing/HPKE by naming its primitives |

| Self-managed key service and custody | No AWS KMS/OSIVault dependency; isolated service, scoped identities, sealed startup, approved operator/hardware custody, root rotation, actual recovery and no runtime private-key export | Synthetic service and operator-unseal webpage implemented; production custody approval, hardening and independent review pending |

| Mandatory genuine PQ scope | Verified stored protection and every required plaintext/key-bearing browser, ingress, key-service and recovery hop; explicit authentication/email scope; downgrade rejection | PQ-only TLS adapter, key-service enforcement, backup-transfer adapter and HTTPS-edge candidate supplied. Real local hybrid/downgrade, browser and adapter checks pass; actual ingress/backup deployment and full-scope approval pending. See PQ_TRANSPORT.md |

| Region and retention | Approved region, exceptional disposal/legal hold and audit/backup/export periods; prove committed submissions survive session/access expiry and remain on the same thread | Documents retained on persistent storage attached to the AWS app instance; no automatic age-based deletion. Region, detailed policies, off-instance backups and recovery targets still open |

| Deployment without AWS KMS | Selected compute/network/identity, private storage without SSE-KMS dependency, PostgreSQL/Redis, protected transport and monitoring; verify storage/archive/backup integrations | Local definitions supplied; runtime KMS protector/settings removed; S3 adapters use SSE-S3; no live deployment evidence |

| Immutable archive | Object Lock COMPLIANCE version retention, denied mutation/delete tests, root-key protection, gap/outage alerting and projection rebuild drill | Append-only triggers, exact-version readback/digest checks, failure tests and independent projection rebuild tested; opt-in AWS denial drill supplied but not run; live retention, external checkpoint and alerts pending |

| Real email | Approved SMTP provider credentials/senders, TLS, delivery/bounce handling, throttling, notification redaction, uncertainty/retry evidence | Private Email SMTP authentication and one explicitly authorized notification reached provider_accepted on 2026-10-28; inbox receipt, bounce handling and deployed public-link verification remain pending |

| Database concurrency | PostgreSQL OTP/idempotency/last-admin races, deadlock/retry behavior and resource revocation races | Real PostgreSQL 17 tests pass for OTP, idempotency, last-admin, reply/revocation races and lock-timeout rollback/retry; forced deadlock rollback/retry also passed; load and broader deployment races pending |

| Operations | Actual root/key-store/data restore and rollback, alert owners, RTO/RPO, unlock/restart availability, rate-limit capacity, safe staged cleanup and growing retained-storage monitoring | Actual isolated pg_dump/pg_restore, encrypted object and key-store recovery tested separately; operational probe and guarded staged cleanup implemented; coordinated production restore, on-call/RTO/RPO/backup policies pending |

| Accessibility and browser assurance | Keyboard/screen-reader and responsive coverage with no blocked critical flows | Staff/recipient workflow with axe checks on document, recipient, accounts/dialog, audit and mobile passes; avatar contrast and Escape focus-return fixed; manual screen-reader/cross-browser audit pending |



The application service is trusted with plaintext and temporary keys. A portal administrator has account/audit authority but no automatic access to another staff member's documents. Infrastructure/key custodians are a separate trust boundary.



The archive database role must be separated from migration/table-owner roles. Triggers protect normal writes; an owner can remove them. Until storage archival is verified, keep **Pending archive** visible. Object Lock does not protect against lost/deleted application root keys, private material or custody recovery authority. Preserve exact object versions and independently protected archive evidence.



The user requires our own system and excludes AWS KMS. This decision does not certify the current candidate or permit a production local root file. See [KEY_SERVICE_ARCHITECTURE.md](KEY_SERVICE_ARCHITECTURE.md) for the implementation/removal sequence and [DATA_RETENTION.md](DATA_RETENTION.md) for retention boundaries. Never delete the only old protector before dependent records/backups are safely migrated.



## Required release evidence bundle



- Protocol specification/version and independent design/implementation findings with required remediation complete.

- Reproducible independent vectors/interoperability, malformed-suite and cross-scope rejection evidence.

- Real PostgreSQL concurrent rotation/read/write tests and interrupted object/database migrations.

- Selected root-custody initialization, sealed restart, recovery and root-rotation drills using actual custodians/hardware, not mocks.

- Proof of no AWS KMS dependency, including S3 document/archive calls, infrastructure and backups; no silent fallback.

- Same-thread retained-file reads after recipient timeout/logout/expiry/revocation; safe orphan cleanup; key/backups available for the retention horizon.

- Verified required PQ transport, protected auditing, operational alerts and approved region/policy/availability decisions.



## P0-5: independent cryptographic approval before real PHI



The production startup block remains mandatory. Real PHI and other real

confidential documents are prohibited in development, test, pilot and production

until the applicable release evidence is approved. Setting `APP_ENV=development`

on a public server does not create an exception. No changes in this review

remove or weaken the startup block.



Replacing the OSIVault dependency with an owned implementation transfers protocol,

implementation and lifecycle assurance responsibility to OneSmarter. It does not

inherit another library's review. The exact hybrid candidate must not be described

as an approved standard merely because its individual primitives are standardized.



Before real-data authorization, the product/security sponsor must allocate budget,

appoint an independent cryptography reviewer and agree a written scope covering:



1. Exact protocol version/commit, combiner, serialization, context binding,

   randomness/nonces, decapsulation failures and downgrade rejection.

2. Key hierarchy, root custody/unseal, workload identities, memory/export exposure,

   version/root rotation, compromised-key response and backup/restore.

3. Dependency provenance, independent known-answer/interoperability evidence,

   malformed-input testing, migration interruption and concurrent reads/rotation.

4. Required PQ transport paths, authentication assumptions and deployment boundaries.

5. Every supplied external finding, including P1-1 through P1-3. Their detailed findings are now tracked in P1_REMEDIATION.md. Forgery rejection and local backup/restore fixes do not close rollback, legacy migration, off-host durability or quorum-custody requirements.



Required deliverables: signed review report referencing an immutable commit,

severity-ranked findings, remediation commits, independent retest evidence and

recorded security/release-owner approval. Funding, reviewer appointment and

acceptance are **pending**. Internal fixes, this checklist and automated test

success are not substitutes for that review. Other release gates also remain.



See [P1_REMEDIATION.md](P1_REMEDIATION.md) for the authenticated-envelope compatibility break and remaining rollout/rollback/custody gates.





## P2 remediation update (2026-10-29)



See [P2_REMEDIATION.md](P2_REMEDIATION.md) for capability configuration, required idempotency headers, administrator MFA reset, staged quotas, evidence and limitations. P2-10 remains partial: metadata caching does not remove all remote crypto calls from transaction locks. Production approval and trusted legacy-envelope migration remain blocked.





## 29 October v2 review follow-up



See [V2_REMEDIATION.md](V2_REMEDIATION.md) for per-finding source status, tests and rollout requirements. Code remediation does not close independent review, provider password rotation, off-host custody, external rollback anchoring or deployment evidence. N-17 remains partial because full audit-history snapshots still hold the key-store lock and post-commit publication crashes need reconciliation. Production remains blocked.



## QA-06–09 validation update



See [QA-06–09 remediation](QA_06_09_REMEDIATION.md). Recipient classical TLS fallback

is now explicit, not PQ-only. Before release, validate real nginx hybrid/classical

negotiation and staff upgrade-only responses; run archive backlog/retry load against

actual PostgreSQL and Object Lock S3; connect archive-lag and sustained-login-failure

signals to operational paging. Local synthetic load and browser tests do not satisfy

those live-service gates.



## RP-04 / RP-05 candidate audit addendum (2026-11-04)

Candidate - internal design decision 2026-11-04, independent review pending.
See DESIGN_DECISIONS_2026-11-04.md, AUDIT_CANDIDATE.md, MUTABLE_FIELD_INVENTORY.md
and REVIEW_HANDOFF_2026-11-04.md. Internal D1-D6 choices are implemented behind
the synthetic-only candidate flag; they are not human cryptographic approval.
The local receiver is test-only. Real separate-account S3, IAM/retention proof,
PQ transport scope, paging and clean-host drills remain pending.
Custodian outage overrides report unverified_override and disable application
document admission until verified export. Signing-key rotation remains disabled.
Unexported tails and unsigned sealed observations retain explicit residual risks.
Current-revision CI is pending; historical green runs cover only their recorded
commits. F-07 is a separate change after RP-04/RP-05/item 10 are merged and tested.
Item 13 is OPEN. Production startup remains blocked.
