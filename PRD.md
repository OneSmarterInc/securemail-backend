# OneSmarter Secure Mail — Product Requirements

> Notification sender update (2026-11-05): OTPs, staff/recipient invitations, and protected-message notifications (including SelfPay) send as `OneSmarter Support <support@onesmarter.com>` using backend environment `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_USE_TLS` and `EMAIL_USE_SSL`. They do not require personal SMTP credentials or an OrganizationSMTP row. The provider must authorize the configured account to send as support@onesmarter.com. Ordinary Nophi email retains approved personal SMTP credentials. Custody readiness checks remain mandatory. This supersedes earlier owner-credential instructions for notifications.

> Audit storage decision — 2026-11-04: staff/admin activity logs remain in the same
> application PostgreSQL database on EC2. External audit archival code is removed; no audit bucket or second automatic
> audit copy is required. Earlier mandatory S3/Object Lock audit requirements are
> superseded. Database logs are not immutable against privileged administrators.
> Key-service security journals, recovery snapshots and cryptographic release
> gates remain separate and unchanged. See [DATABASE_AUDIT.md](DATABASE_AUDIT.md).



> Scope update — 2026-11-04: the owner removed antivirus from the product. Uploads undergo file-type/size validation, authorization, encryption and integrity checks; no malware verdict is produced. Historical scanning results below do not describe current functionality. Other release gates remain.






Updated: 2026-10-29. Status: authoritative product baseline with explicitly open decisions.



The 27 October developer/BA handoff v1.0 is retired. See the

[handoff v1.1 retirement notice](OneSmarter_Secure_Mail_Requirements.md).

Use this PRD for product requirements, API_REFERENCE.md for interfaces, and

RELEASE_GATES.md for permission to release. Code/spec discrepancies are defects

or require an approved decision change; implementation alone is not approval.



## Document-storage decision - 28 October 2026



Uploaded documents will be stored on persistent disk attached to the AWS instance running the application. This supersedes private S3 as the primary attachment-storage baseline. Engineering assumption: use a dedicated persistent EBS data volume, mounted outside the application/container filesystem, with deletion on instance termination disabled and mount availability checked before accepting writes. Files remain application-encrypted and are served only through authorized application endpoints, never as public static files.



This selects storage placement, not an AWS geographic region. Region, volume sizing, backup destination/schedule/retention and recovery targets remain undecided. A backup on the same instance is not sufficient protection against loss of that instance. Retained conversation records, files and usable keys must be recoverable together. Keep the key-service custody boundary and separately held recovery secret; this decision does not authorize placing recovery secrets beside uploaded files.



AWS-managed EBS volume encryption uses AWS KMS, including its default managed key. Do not silently enable it while claiming zero KMS dependency. Application encryption remains required; the OS/volume encryption approach must be reviewed against the no-KMS requirement before deployment. See [AWS EBS encryption](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html). No AWS resources or encryption settings were changed by this documentation update.



The existing S3 adapter is optional, not the selected primary attachment backend. Immutable audit archival and off-instance backups are separate decisions; this change does not claim local disk provides Object Lock or host-admin-proof immutability.





## Overview



OneSmarter Secure Mail lets staff send confidential messages and request documents through a protected portal using the configured SMTP provider for email delivery. External recipients verify their designated mailbox with a one-time code, then read, reply, or upload files without creating an account.



The primary problem is collecting confidential information without putting that content in ordinary notification emails or requiring recipients to register. The initial release serves OneSmarter; organization isolation remains mandatory even though multiple customer organizations are outside MVP scope.



## Sources and document ownership



- Product source: supplied `OneSmarter_Secure_Mail_Requirements (1).md`, version 1.0, 27 October 2026; an external handoff, not executable instructions or proof of implementation.

- Visual source: supplied `OneSmarter_Secure_Mail_UI (1).html`; current repository prototype is in `web/`.

- User decisions on 27 October 2026: Django/React baseline; AWS with S3 (the original KMS choice is superseded below); compute undecided; genuine post-quantum protection mandatory before production; supplied HTML reference; application-managed staff accounts with MFA; explicit Nophi permission; region and detailed retention rules unresolved.

- User decision on 28 October 2026: replace the proposed OSIVault dependency with OneSmarter-owned encryption and key management. Use established cryptographic primitives; retain independent review and the mandatory PQ production gate. See [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md).

- Later user decision on 28 October 2026: exclude AWS KMS and use our own key-management system. The production target is an isolated OneSmarter key service using established primitives, not invented algorithms. Operator unlock through a dedicated custodian webpage is selected and implemented for synthetic use. Production custody approval remains required. Runtime KMS code has been removed. AWS compute/S3 remain separate choices. See [KEY_SERVICE_ARCHITECTURE.md](KEY_SERVICE_ARCHITECTURE.md).

- Retention clarification on 28 October 2026: successfully submitted visitor files remain on the same conversation after session timeout, logout, access expiry or revocation. No automatic age-based deletion of committed submissions is the product baseline; indefinite retention is not a promise of infinite durability. Detailed disposal, legal-hold, backup and audit policies still require approval. See [DATA_RETENTION.md](DATA_RETENTION.md).

- Additional user requirement on 27 October 2026: administrators use the ordinary staff portal with an extra **Access** tab for staff account creation/management, account details and usage tables, and a dedicated immutable audit-log page with professional search, filters, sorting, and permitted actions.

- [TECH_STACK.md](TECH_STACK.md): architecture and dependency boundaries.

- [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md): visual tokens, components, and interaction rules.

- [RULES.md](RULES.md): coding and verification instructions.

- [ROADMAP.md](ROADMAP.md): observed implementation status and delivery gates.



This PRD owns product behavior and the decision register. Record later explicit product-owner decisions here, then reconcile dependent documents. A proposal is not approved merely because it appears in documentation. Repository code and passing tests establish only the behavior actually exercised.



## Personas and permissions



| Persona | Need | Access boundary |

| --- | --- | --- |

| Staff sender / assigned reviewer | Send protected messages; request, read, and respond to documents | Own or explicitly assigned conversations and approved sender addresses |

| External recipient | Respond easily without registration | Designated mailbox grant and its conversation only |

| Company administrator | Use normal staff workflows plus Access: staff accounts, usage, immutable audit logs, and approved settings | All organizational staff accounts are visible for management; normal conversation permissions still apply; no automatic access to others' confidential content |

| Auditor / support | Investigate delivery and access problems | Approved operational metadata; exceptional content access requires an explicit audited grant |

| Background worker | Deliver jobs, scan files, enforce scheduled operations | Least-privilege service identity and scoped work |



All reads, replies, uploads, and downloads require organization and conversation authorization. Shared mailbox verification demonstrates mailbox access, not a person's legal identity or independent MFA.



## Primary flow: request and receive a document



1. Ammar signs in with staff MFA and chooses **Request secure information**.

2. He selects an approved sender address, Sara's email, optional instructions, and access expiry. Blank instructions are allowed.

3. The server validates the submission and creates a protected conversation, recipient grant, encrypted content records, and an outbox record. Storage/object finalization must recover safely from partial failure.

4. The configured SMTP provider delivers a generic invitation with an opaque portal link. Confidential instructions, subjects, filenames, and files are excluded from the notification by default.

5. Sara opens the link, sees the organization and masked destination, and requests a code. The destination cannot be changed by the visitor.

6. The server sends a real code only to the granted mailbox, verifies it once, and creates a short-lived conversation-scoped session.

8. The system stores protected content and records submission success independently of notification delivery. Retries with the same idempotency key represent one logical submission.

9. Ammar receives a generic email notification, signs in to the portal, and reads the submission only after authorization. The service decrypts content for authorized display.

10. Replies stay protected. Expiry or revocation blocks subsequent recipient actions; already downloaded copies cannot be recalled.

11. Accepted files committed to a message remain linked to the original conversation. Session/access expiry is not a deletion trigger; authorized assigned staff retain read access. A new recipient verification may reopen the same thread only while its access grant remains valid. Staged uploads are not completed submissions.



## Other core flows



- **Protected compose:** staff enter To/Cc/Bcc, subject, body/files, expiry; server recomputes routing before any content enters email delivery. Each recipient gets a separate grant and notification without Bcc disclosure.

- **Normal compose:** eligible ordinary messages are delivered through the configured SMTP provider with a visible routing reason. Portal expiry/revocation cannot recall normal email. Preserve supported provider transport protections.

- **Failure recovery:** notification failure leaves stored protected content intact; key-service failure blocks protected operations; failed scans block downloads; interrupted uploads are cleaned up or retried safely.



## Routing contract and precedence



1. Reject malformed input, unauthorized senders, invalid recipients, prohibited files, and invalid empty submissions at the API boundary. Never turn validation failure into normal delivery.

2. Secure-information invitations and existing protected threads remain protected.

3. For an eligible new ordinary conversation, an explicit Nophi toggle plus acknowledgement chooses normal delivery only for staff explicitly granted that permission (D06). A subject word alone never activates the application override.

4. With Nophi disabled, every new message uses the protected portal, including internal-only recipients and explicitly approved company addresses.

5. Ordinary email requires the explicit authorized Nophi override and acknowledgement. Internal recipients never bypass the portal automatically. Pending ordinary deliveries from the retired internal-only rule are cancelled and must be composed again under the new policy; existing sent email cannot be recalled.



Evaluate authenticated identity and every envelope recipient, not an untrusted From header. `sub.onesmarter.com` and `onesmarter.com.attacker.example` are external under this baseline.



The historical pure-policy module retains its subject-matcher tests for reference.

The application supplies the override only after the explicit control is selected;

it never strips or interprets an incidental Nophi word as consent. Every ordinary

send carries the displayed expected route; a changed route is rejected for review.



Show **Normal email — Nophi override** before sending, record the reason and policy version, and never label normal email as inherently unencrypted. Nophi does not classify the content as non-sensitive.



An unauthorized Nophi attempt on a new ordinary conversation must never select normal delivery through the override. Proposed API behavior: reject with an actionable permission error instead of silently choosing a route. Secure-information requests and existing protected threads retain their higher-priority protected behavior. The pure function remains independent of accounts. The Django policy boundary now enforces the explicit permission before persistence/delivery; regression tests cover denial and protected-thread precedence.



The current policy function can return protected for invalid input and short-circuits protected-thread/request flags. It is not an API validator, sender authentication mechanism, or permission grant.



## MVP requirements



| ID | Must-have outcome |

| --- | --- |

| FR-01 | Staff authentication with MFA and authorized sender addresses |

| FR-02 | Compose with To/Cc/Bcc, subject, body, files, and expiry |

| FR-03 | Server-side routing and visible reason; preserve the contract above |

| FR-04 | Dedicated secure-information invitation with optional instructions |

| FR-05 | Generic notification with an opaque link that alone does not authorize reading |

| FR-06 | Single-use email code bound to designated recipient and grant; throttling and scoped session |

| FR-07 | Authorized message/file access and threaded staff/recipient replies |

| FR-08 | Recipient text-only, files-only, and combined submissions |

| FR-09 | Current authorization, expiry, and revocation enforced on every protected request |

| FR-10 | Staff reply notifications by email with portal links |

| FR-11 | Separate delivery, recipient-access, conversation, and per-viewer unread states |

| FR-12 | Authorized search/filter/pagination; searchable fields require D13 |

| FR-13 | Audit metadata without message text, codes, raw tokens, or secrets |

| FR-14 | Durable outbox, bounded retries, idempotent submissions, and controlled notification delivery |

| FR-15 | Sender configuration, service/key health, and actionable failures |

| FR-19 | Administrator-managed staff provisioning and account lifecycle; no public staff self-registration |

| FR-20 | Shared staff portal with an additional authorized Access tab containing Accounts and Audit logs pages |

| FR-21 | Organizational account directory with last login, lifecycle/security details, defined usage metrics, server-side search/filter/sort/pagination |

| FR-22 | Dedicated append-only, immutable-retention audit history with searchable metadata, stable sorting, event details, and authorized exports |

| SEC-01 | Reviewed encryption and key lifecycle for bodies, replies, files, and sensitive metadata |

| SEC-02 | Genuine validated post-quantum protection is mandatory before any production release |

| SEC-03 | OneSmarter-owned key service with no AWS KMS/OSIVault dependency; reviewed root custody, workload authorization, rotation and recovery |

| FR-23 | Committed submissions persist on the same thread independently of visitor-session/access expiry; no automatic timed deletion of submitted documents |

| UX-01 | Mobile and keyboard usability, accessible forms, and clear loading/error/empty states |



## Out of scope for MVP



- Full confidential replies delivered into Proton (FR-16); initial integration is notification-only for protected traffic.

- Intercepting mail composed directly in Proton web/mobile; native compose integration is discovery work (FR-17).

- Browser extensions, Proton partnerships or special APIs, and Tor access (FR-18).

- Anonymous uploads, transferring access by forwarding a link, public file sharing, and recipient account registration.

- Multiple customer organizations as a product offering, advanced business intelligence beyond the required account usage metrics, and full-text encrypted-content search unless separately approved.

- Public staff registration, administrator impersonation, plaintext password display, and editing/deleting historical audit events through the portal.

- Zero-access or client-to-client end-to-end encryption claims; the proposed service manages decryption.

- LLM features, automated content classification, payments, and unrelated integrations.



Post-quantum protection is a release gate, not a deferred nice-to-have. Development with synthetic data can proceed while the architecture is reviewed; do not turn a pilot into an unapproved production exception.



## Administrator experience and staff account lifecycle



Administrators sign in through the same application-managed staff login and MFA flow. They retain the same dashboard, compose, secure-request, assigned conversation, and personal settings experience as ordinary staff. Their additional **Access** navigation item opens two dedicated pages: **Accounts** and **Audit logs**. There is no separate product or unrestricted mailbox view implied by the administrator role.



The Accounts page lists all staff and administrator accounts within the administrator's organization, including invited and deactivated accounts. External recipients are grants, not staff accounts, and do not appear in this directory. Ordinary staff cannot access these pages, underlying APIs, usage totals, or exports by changing a URL. Administrator capabilities are checked server-side and removed promptly when the role is withdrawn.



### Provisioning and management



1. An authorized administrator selects **Create account**, enters the person's name and company email, and selects approved sender addresses and explicit permissions. New accounts default to staff; Nophi defaults off.

2. The system validates organization scope, permitted email/domain, email uniqueness under the documented identity policy, and the administrator's authority to grant each permission. Creating or promoting another administrator requires an explicit privilege-management capability.

3. A short-lived single-use activation invitation is sent to the fixed staff mailbox. The administrator never sees or sends a permanent password. Account creation and invitation delivery have distinct statuses; delivery retries do not create duplicate accounts.

4. The invited employee verifies activation, sets their own password, and enrolls in the approved MFA method before accessing confidential workflows. Expired or superseded invitations cannot activate accounts; suspended/deactivated accounts cannot be activated through old links.

5. Permitted row actions include view details, edit approved profile fields/sender permissions, resend or cancel pending invitation, suspend/reactivate/deactivate, initiate password recovery, revoke sessions, and review that account's audit history. MFA recovery follows a separate verified procedure; it must not silently bypass MFA.

6. Sensitive changes require a clear review/confirmation, recent MFA verification where appropriate, and an audit reason. Passwords, recovery secrets, and MFA seed values are never displayed in account details.



Proposed lifecycle: **Invited → Active → Suspended or Deactivated**; permitted reactivation is an explicit audited action. Activation expiry and temporary authentication lockout are separately represented, not confused with deliberate deactivation. Protect the last active administrator and prevent self-lockout or concurrent role changes from removing all administrative access. Provision the first administrator through a controlled, audited bootstrap procedure, never a public signup route.



Suspension/deactivation revokes staff sessions and blocks subsequent protected operations and new sending. Workers recheck authorization before executing pending user-originated sends. Preserve conversations and audit attribution; ownership stays with the original staff member through deactivation and reactivation (D10); recipient access/submissions are blocked while the owner is inactive. Changing a login mailbox requires a dedicated verified flow with session/invitation invalidation, not a casual profile edit.



### Account directory and details



The default table shows name, login email, role, account status, MFA status, last successful login, period usage, and an Actions menu. Account details or configurable secondary columns expose the following fields without requiring an unusably wide table:



| Field | Meaning / behavior |

| --- | --- |

| Account ID, name, login email | Stable identity plus permitted profile fields; email is not a password or sender-authorization proof |

| Role and explicit permissions | Staff/admin, approved sender addresses, Nophi permission; show allowed management actions |

| Account and invitation status | Invited/active/suspended/deactivated; pending/expired/cancelled invitation and delivery failure separately |

| MFA status | Required/not enrolled/enrolled/recovery pending; never secret material |

| Created at / created by | Server timestamp and creator reference; bootstrap accounts identified explicitly |

| Last successful login | Completion of password and required MFA; Never for an account that has not completed login |

| Last activity | Timestamp of the last qualifying authenticated user action; distinguish it from login and background refresh |

| Last modified / status changed | Time, actor, and approved reason where permitted |

| Active sessions | Count and revocation action; no raw session identifiers or cookies |

| Usage | Selected-period activity counts plus current storage/assignment gauges as defined below |



Use server-side search across approved name, email, and account-ID fields; filters for role, status, MFA status, Nophi permission, and login/activity date range; and ascending/descending sorting on supported columns with visible arrows. Default proposal: newest created first, stable account-ID tie-breaker; Never/unknown timestamps sort last in either direction. Provide pagination, result counts, Clear filters, and an explicit no-results state. Proposed page sizes are 25/50/100 with a server-enforced maximum.



### Usage definitions



Usage is operational metadata, not access to confidential content or employee surveillance. Proposed default period: last 30 days, with explicit start/end dates and timezone. Show **Updated at** and report unavailable data as unknown, not zero.



| Metric | Counting rule |

| --- | --- |

| Protected messages / secure requests / normal messages | Separate counts of unique committed staff send/request actions initiated by the account during the period; retries and notification fan-out do not inflate totals; counts do not prove delivery |

| Staff replies | Unique committed replies authored by the account during the period |

| Recipient submissions received | Unique submissions attributed to the assigned staff owner at receipt time; historical attribution does not change after reassignment |

| Files uploaded / bytes uploaded | Accepted file submissions attributable to the uploader or receiving owner at submission time, shown separately; reject/failure counts separate; no multiplication by downloads or retries |

| Current assigned conversations | Count of presently assigned conversations; separate from historical period activity |

| Delivery failures / pending notifications | Current operational job counts scoped to the account; separate from logical message counts |



Document shared-conversation storage attribution before implementation (D10/D16). Count each object once in organization totals; do not sum overlapping per-account views. These metrics need neither message-body search nor filenames in the directory.



## Immutable audit-log page



The Access → Audit logs page is a dedicated administrator workspace, not a developer console or a list of editable database rows. It shows organizational security and operational events, including the administrator's own actions. Read/export capabilities may be delegated explicitly to an auditor without granting account-management or message-content access.



Record account creation/activation/status/profile/role/permission changes, invitation lifecycle, login successes/failures, MFA/recovery events, logout/session revocation, approved sender changes, Nophi use/denial, conversation access/reply/download/revoke outcomes, notification failures, file scan outcomes, key-operation metadata, settings changes, and audit access/export. Never record submitted passwords, codes, tokens, content, sensitive filenames/subjects, or unrestricted request payloads.



| Event field | Requirement |

| --- | --- |

| Event ID and organization | Unique immutable ID and tenant boundary |

| Occurred at / recorded at | Server-controlled UTC timestamps; distinguish delayed ingestion; UI displays an explicit timezone |

| Actor | Stable account/service/recipient-grant reference, actor type, and role at event time; unknown actors remain unknown |

| Action and category | Defined action codes and human-readable labels such as Account suspended or Nophi denied |

| Target | Resource type and opaque ID; include a target account where relevant, without confidential content |

| Result | Success/failure/denied and safe reason code; distinguish request intent from completed outcome |

| Change metadata | Allowlisted non-secret before/after values or references, reason, correlation/request ID, relevant policy version |

| Integrity/archive state | Verified archive reference or Pending archive / Verification failed; never imply archival protection before confirmation |



Search by event ID, authorized actor/target identity, target resource ID, action code, or correlation ID. Filter by date/time, actor, action/category, target type/account, and outcome. Sort supported timestamp/actor/action/result columns in either direction with visible arrows, stable event-ID tie-breakers, and server-side pagination. Default is newest recorded first. New incoming events must not unexpectedly move rows while an administrator inspects a result page.



Permitted actions: **View details**, **Copy event ID**, **View related events**, and **Export filtered results** for administrators/auditors explicitly allowed to export. Exports are scoped, redacted, bounded or queued, audited, and time-limited; recheck access on download. No Edit, Delete, Clear history, or destructive bulk action exists. Separate linked correction events may explain an error while preserving the original.



**Immutability contract:** historical events cannot be modified or deleted by portal users, including administrators, through UI or API. Retained canonical audit records must also have storage-enforced protection for the approved retention interval; application-level append-only code alone is insufficient. Keep a searchable projection with reconciliation against the protected archive, show ingestion/archival health, detect gaps/tampering, and preserve original attribution after account deactivation. Do not promise protection against every infrastructure compromise or indefinite retention without an approved design. D15 covers archive retention, evidence, controlled end-of-retention disposal, and any minimized network/device metadata; it does not make immutable logs optional.



## Security and privacy outcomes



- Protect data in transit and at rest; do not leak confidential content into notifications, telemetry, queues, browser persistence, or backups.

- Keep wrapping keys controlled by the managed key service. The backend may temporarily receive data keys and plaintext for approved processing; this is a trusted-service design.

- Use reviewed, versioned envelopes and authenticated organization/conversation/message/object context. Document key rotation, old-version recovery, and backup restoration.

- Validate genuine PQ mechanisms separately for browser-to-service, stored-content/key-establishment, and service-to-email-provider paths. A signature, ordinary TLS, AES label, AWS KMS adoption, or an in-house cryptographic implementation alone is not acceptance evidence. D03 defines exact coverage and proof.

- Apply staff MFA, recipient OTP throttling, protected session cookies, CSRF controls, per-request authorization, and token/code redaction.

- Access expiry does not imply deletion. Retention, legal hold, export, and jurisdiction requirements must be decided before real-data use.



## Proposed operational defaults — not yet approved



| Setting | Proposal | Open detail |

| --- | --- | --- |

| OTP | Six digits, ten minutes, one use | Aggregate issue/attempt limits and delivery lifecycle |

| Attempts | Five per challenge | Recipient, grant, IP, and sender abuse limits |

| Resend | Thirty-second cooldown | Hourly/daily caps and replacement of prior challenges |

| Recipient session | Fifteen minutes | Idle versus absolute expiry |

| Recipient access | Seven days; one/seven/thirty-day choices | Staff access and conversation lifecycle are separate |

| Attachments | Ten files, 25 MB combined | Approved types, per-file limits, scan engine |

| Recipient replies | Private recipient-to-staff by default | Group and reply-all behavior |



## Acceptance and success measures



A release must demonstrate the complete Ammar/Sara flow with actual delivery evidence, authorized reading, and effective revocation. It must also demonstrate internal/external/mixed routing, exact Nophi behavior, and protected-thread/request precedence.



Required negative cases include forwarded links, wrong/expired/reused codes, concurrent verification, revoked active sessions, cross-organization/object access, Bcc exposure, duplicate requests, malicious files, key unavailability, ciphertext/context tampering, and unsupported PQ algorithms without silent downgrade.



Administrator acceptance also requires: staff denied direct Access/API/export access; admin ordinary conversations remain scoped; create/invite/activate with MFA; duplicate creation handled safely; suspended sessions and pending sends denied; role/Nophi changes enforced immediately; last-administrator concurrency protected; last-login recorded only after MFA; usage not inflated by retries; accessible server-side sorting/search/pagination; audit mutations denied even to admins; archive overwrite/deletion rejected during retention; corrections append rather than replace; export scope/redaction audited; archive failure/gaps visible and recoverable.



Track invitation-to-submission completion, notification outcomes, verification failures, scan failures, queue delay, key-service failures, and restore results using non-sensitive operational metadata. Numeric latency, availability, recovery-time (RTO), and acceptable data-loss (RPO) targets remain D12; do not invent service guarantees.



## Decision register



| ID | Decision | Status / accountable role |

| --- | --- | --- |

| D01 | Django 5.2 LTS + DRF, React 19 + TypeScript, PostgreSQL, Celery/Redis, Docker | Implemented baseline; exact installed dependencies recorded in requirements.lock and frontend/package-lock.json |

| D02 | Hosting and private storage | AWS application instance with attached persistent document storage; supersedes primary S3 storage. AWS KMS remains excluded. Instance specification, region, networking, backups and database/broker placement remain open; engineering/operations |

| D03 | Genuine PQ protection before production | Mandatory by user decision; exact algorithms, coverage, compatibility, and acceptance evidence open; security + product owner |

| D04 | Supplied HTML visual direction | Selected reference; accessibility refinements in DESIGN_SYSTEM.md |

| D05 | Staff authentication provider and MFA recovery | Application-managed accounts implemented with authenticator TOTP, single-use recovery codes, admin-issued password recovery and session revocation; production recovery policy still needs approval |

| D06 | Who may use Nophi | Explicit permission only; backend enforcement and actionable rejection implemented and tested |

| D07 | Nophi interaction | Explicit toggle and acknowledgement required; subject text is retained and does not activate the override |

| D08 | Retention, deletion, legal hold, exports, data residency | Committed submissions have no automatic age-based deletion and survive access/session expiry. Detailed disposal/legal-hold, audit/export/backup periods and region remain unresolved before real-data use; see DATA_RETENTION.md |

| D09 | OTP/session/attachment default approval | Proposed table above; product/security |

| D10 | Deactivation and ownership | User decision 29 October: preserve conversation ownership; disable staff access while deactivated and restore after reactivation/fresh login. Do not reassign automatically. Block recipient access/submissions while the owner is inactive. Shared ownership/exceptional access remains out of scope |

| D11 | Per-recipient/group reply visibility and revocation scope | Private recipient-to-staff proposed; product/security |

| D12 | Latency, availability, RTO/RPO, operating budget | Open; product/operations |

| D13 | Searchable fields with encrypted subject/body | Metadata-first proposed; product/security/engineering |

| D14 | Administrator provisioning and Access workspace | Required by user: normal staff portal plus Accounts and Audit logs; controlled activation/lifecycle and permission model specified above |

| D15 | Immutable audit storage and retention | Immutable logs required by user; archive mode/duration, export limits, metadata minimization and disposal approval open; resolve with D08 before real-data use |

| D16 | Account usage details and table defaults | Required by user; current 7/30/90-day counters and retained-storage gauges implemented; shared ownership remains outside current assignment model |

| D17 | Cryptographic implementation ownership | User requires our own system, replacing OSIVault. OneSmarter v2 envelopes, key versions, rotation and migration implemented using cryptography; protocol/PQ coverage review remains mandatory |

| D18 | No external managed KMS | User excludes AWS KMS; isolated OneSmarter key service is the target. Runtime KMS adapters/settings removed; S3 uses SSE-S3; isolated candidate and custodian webpage implemented, production approval pending |

| D19 | Root custody and service operation | Operator unlock through the separate custodian page is implemented for synthetic use. Named custodians, quorum/hardware policy, production boot/unseal and recovery approval remain open. A local development root file is not production custody |



## Terminology



- **Grant:** permission for one designated mailbox to access a conversation.

- **Outbox:** durable database record of work that must happen after a business transaction.

- **Idempotency:** retries represent one logical action rather than duplicate records.

- **Data key / DEK:** encrypts content; stored long-term only in protected form.

- **Wrapping key / KEK:** protects data keys; managed separately from stored content.

- **PQ:** post-quantum; requires evidence for the specific mechanism and path being claimed.



## SMTP provider selection update - 28 October 2026



The user selected Private Email (`mail.privateemail.com`, port 587 STARTTLS) and `info@kormic.ai` for the local SMTP profile, superseding the earlier Proton delivery plan. Secrets remain outside tracked files. Provider credentials are configured but real sending has not been exercised; delivery/bounce limits and authorized From-address mapping remain release requirements. Protected traffic stays notification-only. Earlier Proton-native integration exclusions are historical and do not grant a new integration scope.









## Portal separation and deployment interface - 2026-10-28



Staff and administrators require exact @onesmarter.com accounts. Recipients may use any valid mailbox. Staff enter through /staff/; invitation links enter through /recipient/ and use a separate API namespace and session cookie. Normal user pages no longer display development banners, test-mailbox controls or engineering release requirements. Operator test tools require explicit opt-in. Local captured notifications are explicitly marked not emailed. This supersedes earlier instructions to show development-mode banners on customer pages; deployment status remains documented and enforced on the server. See [DEPLOYMENT.md](DEPLOYMENT.md) for compatibility, configuration and outstanding release blockers.





### Recipient session and transient cleanup clarification (29 October 2026)



Recipient access has a 15-minute idle window and an explicit eight-hour absolute lifetime per verified session. Pointer, keyboard, scrolling and wheel interaction count as activity; polling alone does not. A fresh mailbox code is required after expiry, and is sent only when the recipient explicitly requests it. If the invitation token remains in component memory, show an Email me a code action and preserve the in-memory draft and accepted attachments. After reload, an active HttpOnly session can resume the conversation; if it has expired and no invitation token remains, direct the recipient to their latest invitation email instead of submitting an empty token. Transient service/network errors offer a read retry and never trigger OTP delivery. Revocation, inactive ownership and conversation expiry continue to block access. Staff replies retain earlier invitation hashes as described below. Draft persistence is limited to the mounted page, not a reload or reopening an email link.



Celery Beat schedules bounded cleanup every 15 minutes for abandoned, uncommitted uploads older than 24 hours and obsolete rate-limit rows idle for more than two days. Committed messages/documents are excluded; their retention is unchanged. Explicitly cancelled or interrupted uploads may leave a reservation until cleanup completes. Administrator MFA reset invalidates the existing password and requires the employee's one-time emailed recovery link before password setup and MFA re-enrollment.





### Approved company mailbox exception (30 October 2026)



The operator-approved exact address info@kormic.ai may be configured in COMPANY_EMAIL_ALLOWLIST and treated as a company mailbox for account eligibility, login, session validation, authorized sender assignment and internal-recipient routing. This exception does not admit other kormic.ai addresses, create an account or automatically assign administrative privileges. Account roles, MFA and sender assignment remain enforced. Mailbox eligibility does not configure delivery. The organisation SMTP and individual encrypted staff credentials described below govern sending.



### Staff session polling resilience



Conversation status refresh runs in the background and leaves the reply form mounted. Preserve unsent text, selected attachments and active uploads during refresh and temporary errors; show refresh errors alongside the last loaded conversation. A successful reply clears submitted inputs but leaves its confirmation visible after the thread refreshes. Never reuse a previous conversation's data after navigation, and clear retained content on confirmed authentication/authorization denial or an unavailable conversation (401/403/404).



Attachment downloads use authenticated, non-cached fetches and check HTTP status before creating a downloadable blob. Failures show an in-page error rather than navigating to an API response; 401 responses trigger normal session-expiry handling. Recipient invitation tokens remain in component memory for explicit re-verification. Cancel active downloads when the thread unmounts and release temporary object URLs after download handoff. A successful download does not imply that a saved local copy can later be revoked.



After a successful session check, temporary polling failures retain the last confirmed session and leave the current page mounted, including unsent draft state and active uploads. Show a session-check-unavailable banner with an explicit retry action; continue automatic periodic/visibility checks and clear the banner on recovery. Retained UI state grants no extra API authority: the server still checks each request. A confirmed 401 or successful session response with no user clears staff authentication. Before any successful session check, show a retryable loading/error screen instead of authenticated content. Ignore stale polling results after logout/session expiry or a new sign-in.



### Recipient invitation link continuity



Staff replies issue fresh notification links while retaining previous invitation hashes for the same recipient grant. Original and subsequent links remain valid only while the grant and conversation are active and unexpired and the owner remains active. Every link still requires email OTP verification; links do not grant direct document access. Retained hashes contain no plaintext invitation secrets. Links invalidated before token-history support was deployed cannot be reconstructed from the current grant hash; send a fresh notification for those recipients.



### Staff login and idle controls (31 October 2026; QA-08/09)



Login token buckets allow 10 attempts per account/source network per minute and

50 per source IP per minute. IPv4 uses /24 and IPv6 /64. These hard budgets run

before password hashing. An exhausted network cannot lock the account on an

unrelated network; correct passwords still require MFA. Sustained known-account

failures generate audit/monitoring alerts and advisory exponential Retry-After

responses, without an application-global hard login lock.



Staff sessions lock after 15 minutes of inactivity (configurable) with an eight-hour

absolute lifetime. Background polling does not renew activity. A server-validated

activity request follows real UI interaction. The UI warns one minute before locking

and hides protected content even if connectivity fails. See QA_06_09_REMEDIATION.md

for the shared-network and distributed-abuse tradeoffs.



## Organisation SMTP and secure conversation threads (31 October 2026)



This replaces the earlier shared Proton/Private Email sender configuration and the earlier separate-copy rule for To/Cc recipients.



- Administrators configure the organisation SMTP hostname, verified TLS submission mode (STARTTLS/587 or TLS/465), enabled state, and sender display name in Connections. Staff save their own approved SMTP email and password there. From and Reply-To use that same staff email; the application never falls back to a shared provider credential. The chosen local transport is smtp.ionos.com:587 with STARTTLS and display name OneSmarter Support. Real authentication requires each staff member's provider-supported credential; it has not been verified by automated tests.

- SMTP passwords are encrypted using the existing document encryption/key-service boundary, bound to organisation and staff identity. They are write-only in APIs, excluded from audits, and included in key migration. Admin transport changes require staff to re-enter credentials before sending to the changed destination. SMTP connections reject private/reserved network destinations and verify TLS certificates.

- Single-recipient protected sends continue the existing owner-recipient chat. Multiple visible To/Cc recipients share a separate thread, reused for the same owner and visible participant set. Each BCC recipient receives a private copy in their own chat. BCC identities are never returned to other recipients. Adding/removing visible participants starts a different group thread; it does not reveal old group history.

- Messages display author, date, and expandable From/To/Cc details. A BCC viewer sees only their own BCC status; the owning staff can see the BCC metadata on their original sent message. Reply to sender is private to that message's author. Reply all reaches the owning staff and visible To/Cc participants; BCC copies cannot Reply all. Private recipient-to-recipient replies are hidden from other participants, including staff, by API and attachment authorization.

- Notifications contain a generic secure-message notice and portal button, never the confidential subject/body/files. The recipient verifies their own mailbox using OTP. Recipient portal replies notify the staff owner when the owner is a recipient of that reply. Ordinary incoming email is not imported; notifications instruct recipients to reply in the portal.

- Existing ciphertext and conversation identifiers are preserved. Historical group threads are not merged or reparented. New direct-chat mappings can adopt eligible existing private threads; unauthenticated legacy ciphertext remains subject to the existing migration gate.

- Nophi remains a separately authorized ordinary-email option. These group-thread and private-copy rules apply to protected portal traffic.



## Local evidence preservation and OTP sender update — 31 October 2026



See [EVIDENCE_ARCHIVE.md](EVIDENCE_ARCHIVE.md) for the implemented capture catalog, original-file hashes, server-download provenance, encrypted create-only local bundles, verified exports, legacy backfill and optional RFC 3161 verification. The user selected local preservation for now and an unset TSA. Deployment must not silently switch to AWS. Local preservation is not administrator-proof cloud WORM; pending timestamps are not trusted timestamps. Hospital-list reconciliation is excluded.



Emailed recipient OTP challenges authenticate through the organisation SMTP transport using the conversation owner's encrypted staff SMTP username and password. Only the From/envelope sender is support@onesmarter.com; Reply-To remains the staff address. No separate support password is required. The provider must authorize each staff account to send as support@onesmarter.com; rejected delivery fails closed without a sender fallback. Missing staff credentials block OTP delivery. Staff authenticator TOTP is unchanged. Ordinary conversation notifications retain each owning staff member's SMTP sender.



Local key-service calls now prefer the IPv4 loopback listener while retaining localhost certificate verification and PQ requirements. Every wrap/unwrap still contacts the service; no plaintext, data keys or readiness result is cached to achieve the speedup. Initial workspace session checks time out after eight seconds with retry; authenticated drafts survive transient polling failures.





## Required capture provenance — 31 October 2026



New uploaded files require both a source document HTTPS URL and an original download timestamp with timezone. Missing, invalid, timezone-free or future download times are rejected before staging. The shared staff/recipient upload form collects one file at a time with its own provenance. These values remain uploader-declared, not independently verified. Direct URL capture records the requested/final URL and actual server download-completion time automatically. Finalization also rejects older staged files missing these fields; upload them again with accurate provenance. Existing committed captures and explicit legacy backfills remain unchanged and honestly report unknown fields. No earlier download time is inferred from file modification time or portal upload time. Files with no known web source cannot be newly captured through this workflow; do not invent a URL or time. TSA verification and local-storage limitations are unchanged.





## Unified conversation entry — 31 October 2026



One New conversation action replaces the separate message and information-request actions. The single form accepts optional subject/message for protected invitations, files, To/Cc/Bcc and an access deadline. Default payload uses the existing secure_request contract; authorized Nophi explicitly selects ordinary mode with its required subject/content and acknowledgement. Existing /request links remain a compatible alias to the same composer. Existing protected conversations cannot be downgraded. Page headers omit redundant category labels; conversation headers combine navigation, title/date and delivery status.





## Recipient access policy update — 2026-10-31



This supersedes earlier 1/7/30-day conversation/link expiry requirements. Recipient invitation links do not expire automatically. Existing conversation deadlines are retained only as historical data and are not enforced. New conversation records use a null deadline. Continued direct/group chats preserve old invitation token hashes; new messages do not invalidate existing stored links. All links require mailbox OTP verification and remain subject to grant/conversation revocation and active-owner checks. OTP expiry, recipient idle timeout and absolute session lifetime remain enforced. The compose expiry selector is removed; access details say Until revoked. Older clients may send expiry_days for compatibility, but it does not impose a deadline. Previously deleted token hashes cannot be reconstructed; those recipients need an available invitation.





## Recipient reply routing update — 2026-10-31



Recipient private replies always go to the assigned staff owner, even when the selected message was authored by another recipient. They are visible only to that replying recipient and the owner, including attachments; the owner receives a notification. Reply all remains shared with eligible To/Cc recipients and visible to the owner. BCC private copies cannot reply all. Staff can still reply privately to a recipient. Historical recipient-to-recipient private messages are now visible to the assigned owner for review; administrator status alone does not grant content access. Submission audit metadata records reply mode and whether a recipient reply is private to the owner. This supersedes earlier recipient-to-recipient private reply behavior.



## QA-06/07 policy update (31 October 2026)



Audit Object Lock archiving uses chained batches of up to 1000 events, continuous

bounded draining and a 15-minute oldest-pending alert threshold. Verification precedes

archive status. Public recipient TLS may use classical X25519 when hybrid ML-KEM is

unavailable; this hop is no longer claimed to be PQ-only. Staff content and internal

controlled hops retain the hybrid requirement. Measure recipient group support during

pilot. Independent cryptographic review remains a production gate.

