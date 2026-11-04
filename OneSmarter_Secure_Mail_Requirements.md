# OneSmarter Secure Mail — handoff v1.1 retirement notice


> Scope update — 2026-11-04: the owner removed antivirus from the product. Uploads undergo file-type/size validation, authorization, encryption and integrity checks; no malware verdict is produced. Historical scanning results below do not describe current functionality. Other release gates remain.


Version 1.1 • 29 October 2026 • BA, engineering, QA, security and operations



## Status and authoritative sources



The developer/BA handoff v1.0 dated 27 October 2026 is **retired as an

implementation or acceptance specification**. This includes downloaded copies

named `OneSmarter_Secure_Mail_Requirements (1).md`. Preserve old exports only as

historical evidence; do not implement their endpoint tables, provider choices,

architecture or prototype-status columns. This notice supersedes that baseline;

it does not rewrite copies already distributed outside this repository.



Use these version-controlled documents together:



| Subject | Authoritative source |

| --- | --- |

| Product behavior, permissions, decisions, scope | [PRD.md](PRD.md) |

| Architecture and tools | [TECH_STACK.md](TECH_STACK.md) |

| Actual API contract | [API_REFERENCE.md](API_REFERENCE.md), checked against `backend/config/urls.py` |

| UI implementation/design | `frontend/src/` and [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md) |

| Crypto/key custody | [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md), [KEY_SERVICE_ARCHITECTURE.md](KEY_SERVICE_ARCHITECTURE.md) |

| Storage/retention | [DATA_RETENTION.md](DATA_RETENTION.md) |

| Release permission and unresolved security evidence | [RELEASE_GATES.md](RELEASE_GATES.md) |

| Test evidence and progress | [TESTING.md](TESTING.md), [ROADMAP.md](ROADMAP.md) |



If code and PRD disagree, record a defect or an approved requirement change.

Code is evidence of implementation, not automatic authority to change a product

requirement. An internal test result cannot override a release gate.



## Material changes since v1.0



- Django/React staff authentication, MFA, recipient OTP, secure intake, storage,

  use. The original static prototype is historical; no private hosted prototype

  link is required to use or review this repository.

- Private Email was selected for local SMTP testing. Production requires an

  approved company-domain sender, a credential mapping and verified domain

  authentication. Provider/mailbox selection for that production configuration

  is pending; neither the old Proton assumption nor a successful SMTP test is

  production approval. See [SMTP_SENDERS.md](SMTP_SENDERS.md).

- OSIVault and AWS KMS are excluded. OneSmarter owns the current hybrid candidate

  and isolated operator-unsealed key service. No independent approval is claimed.

- Uploaded documents target persistent storage attached to the AWS app instance;

  off-instance backup destination, retention and recovery targets remain open.

- Secure-information requests allow a blank body and always stay protected.

  Recipient endpoints use `/recipient-api/`; use the API reference instead of the

  retired invitation-path table.

- Test counts are dated evidence, not a permanent total or certification. Use

  TESTING.md and actual CI results; skipped integrations are not passes.



## Change control



Each material decision change must update the PRD decision register and affected

architecture/API/operations documents in the same change. Add dated evidence to

ROADMAP/TESTING when behavior is verified. A release reviewer must check for

contradictory active documents and identify the exact commit under review.

BA owns requirement acceptance, engineering owns implementation evidence, and

security/release owners approve the applicable production gates. Named owners,

external review budget and sign-off records still need assignment; this notice

is not their approval.

