# API-key validation — 2026-11-12

Implemented in the current backend/frontend worktrees; not deployed to production.

- Backend full local suite: 639 passed, 19 skipped (SQLite, synthetic mode).
- Includes five new API-key regression tests covering authentication, scopes,
  expiry/revocation, MFA/CSRF, encrypted sends, idempotency, cross-key isolation,
  disabled owners, sealed-service rejection, HTTPS and rate limits.
- Frontend TypeScript/Vite production build passed.
- Playwright API-key creation/show-once/revocation tests passed at 1440px and
  360px with mocked synthetic API responses, axe checks and no page overflow.
  Both screenshots were visually inspected.
- Browser tests are UI evidence; backend tests separately verify persistence and
  authorization. They are not evidence of live SMTP delivery or PostgreSQL races.

Local app uses existing account/data files, with a database backup before applying
migrations. Local mail is development capture, not SMTP. The custodian must unseal
the retained local key store manually. Existing credentials and recovery keys are
not regenerated. The local Careers development servers were stopped; hosted
Careers was not modified.

The API currently supports text messages to one recipient and reads scoped to the
key that created the conversation. No attachments or general administration API.
Revocation blocks future key requests but does not cancel accepted queued mail.
See PUBLIC_API.md for exact schemas, permissions, errors and examples.

## 2026-11-24 extension

The admin list now supports combined name, status and permission filtering before
pagination, with a clear-filters action. Generation, show-once secrets, expiry,
MFA and revocation remain available.

Added immutable, encrypted, per-key notification templates and JSON previews at
`/api/v1/templates`, `/api/v1/templates/preview` and `/api/v1/templates/{id}`.
Message creation accepts `template_id`. Restricted HTML/CSS is reconstructed
from allowed tags and values; the application owns the verification link.
Template text is ordinary email content, not protected message content.

Focused API-key/template regression suite: 16 passed. Includes filter validation,
organization isolation, preview without sending, encrypted template storage,
creation idempotency, cross-key rejection, multipart captured delivery and nine
unsafe-markup cases. SMTP rendering verification uses the in-memory backend.
Desktop/mobile filter + lifecycle tests: 2 passed with axe checks. Build passed.
No production deployment, PostgreSQL concurrency or live email delivery claimed.
Migration 0028 adds templates and depends on the unshipped API-key migration 0027.

Final complete backend regression run after the template extension: 650 passed,
19 skipped in 172.86 seconds (SQLite/synthetic). Ruff check and formatting check
passed. makemigrations --check --dry-run reported no model changes; its default
local database path was unavailable, so production migration history was not
checked. All migration files were exercised by the isolated test database.

## Booking, branding, reply policy and mailbox extension — 2026-11-24

Implemented locally in the existing runtime worktrees:

- Explicit SelfPay booking create/read/confirmation methods with owner/scopes,
  key isolation, idempotency and provider-only delivery. Legacy HMAC triggers unchanged.
- Separate normal/SelfPay notification profiles. Custom, restricted notification
  and OTP HTML/CSS previews; encrypted presentation snapshots; validated PNG logo
  and contrast-checked portal colors. Application-owned OTP and verification links.
- Recipient-bound automatic OTP requests on API invitations. No API retrieval of
  OTPs; no private subject/body in notification emails.
- Recipient replies/uploads default disabled. Only JSON reply=true enables them;
  the latest send controls the stream policy. Backend checks accompany hidden UI.
- Repeat sends reuse one key/sender/recipient stream. Verified API recipients can
  browse their own mailbox across senders and switch without extending session
  deadlines. Other mailboxes, legacy grants, revoked access and cross-key API reads
  remain denied. Existing records are not merged or deleted.

Full synthetic backend regression: **676 passed, 19 skipped**, 178.16 seconds.
Windows sandbox restrictions blocked hard links/local TLS servers in an initial
run; the completed run used the permissions those isolated tests require. A rate
limit test now freezes its clock to avoid slow-machine token-refill flakiness.
After the final inbox audit-record addition, all three inbox regressions passed.
After the final recent-message ordering adjustment, the complete focused API
suite passed: **42 passed** in 7.27 seconds, with Ruff/format/diff checks passing.

Frontend: TypeScript/Vite build passed; four Playwright scenarios passed at
1440px/360px covering key lifecycle, automatic OTP, noneditable mailbox, resend
cooldown, protected message display, reply controls and sender-archive switching.
Axe checks passed on tested admin/verification states. Browser fixtures are mocked;
they are not live SMTP/OTP delivery evidence. Desktop/mobile screenshots were
inspected, and sample message content replaced the initial empty test fixture.

Ruff and diff whitespace checks passed. Migrations 0027–0032 are unshipped and
were applied only to temporary test databases. Migration dry-run found no missing
model changes; default local database history could not be checked. Existing
data, production environment, certificates and unseal/recovery keys were not changed.
No push, AWS/Vercel deployment, real-email delivery or PostgreSQL concurrency
validation was performed. Production/security review gates remain outstanding.
