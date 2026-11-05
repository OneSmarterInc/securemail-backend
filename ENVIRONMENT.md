# Local environment configuration

> SelfPay SMTP update (2026-11-05): enable `SELFPAY_SMTP_ENABLED=true` and configure `SELFPAY_EMAIL_*` plus `SELFPAY_FROM_EMAIL` to route SelfPay secure-portal invitations, OTPs, confirmations and message notifications through their dedicated SMTP account. From and Reply-To both use `SELFPAY_FROM_EMAIL`. Other system mail keeps the general configuration below. See [SELFPAY_SMTP.md](SELFPAY_SMTP.md) for variables and deployment scope.

> Notification sender update (2026-11-05): OTPs, staff/recipient invitations, and protected-message notifications (including SelfPay) send as `OneSmarter Support <support@onesmarter.com>` using backend environment `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_USE_TLS` and `EMAIL_USE_SSL`. They do not require personal SMTP credentials or an OrganizationSMTP row. The provider must authorize the configured account to send as support@onesmarter.com. Ordinary Nophi email retains approved personal SMTP credentials. Custody readiness checks remain mandatory. This supersedes earlier owner-credential instructions for notifications.

> Audit storage decision — 2026-11-04: staff/admin activity logs remain in the same
> application PostgreSQL database on EC2. External audit archival code is removed; no audit bucket or second automatic
> audit copy is required. Earlier mandatory S3/Object Lock audit requirements are
> superseded. Database logs are not immutable against privileged administrators.
> Key-service security journals, recovery snapshots and cryptographic release
> gates remain separate and unchanged. See [DATABASE_AUDIT.md](DATABASE_AUDIT.md).


Updated 29 October 2026.

The repository-root `.env` is the local Django API/worker configuration file.
It is ignored by Git and excluded from Docker builds. `.env.example` is the
tracked, shareable template; it contains no credentials. Production remains
blocked by the release gates regardless of values in either file.

For a new checkout, install `requirements.lock`, copy `.env.example` to `.env`,
and run `python scripts/init_local.py` to initialize missing synthetic secret
files. Never replace existing wrapping keys to fix configuration errors.

Django loads only this exact root file, regardless of the current working
directory, using python-dotenv 1.2.4. Existing process environment variables
win, including explicitly empty values. Variable interpolation is disabled so
credential strings containing `${...}` remain literal. Use quoted values for
spaces or `#`. Set `DJANGO_READ_DOT_ENV=false` in the process environment to
ignore the local file for isolated tests or managed deployment. Restart API and
workers after editing; changing a file does not update running process settings.

## Current local profile (31 October 2026)

The local portal runs on localhost:5173 with a loopback Django API. SQLite and encrypted documents remain under .runtime. The configured key protector is now the isolated key service with PQ transport; local wrapping-key fallback is removed. The key service starts sealed and must be explicitly unsealed through custody procedures before encrypted content or staff SMTP passwords can be used. Never replace keys to resolve a startup error.

Organisation SMTP is configured through Connections, not a shared environment password. The selected common server is smtp.ionos.com, port 587, STARTTLS, display name OneSmarter Support. Each staff member enters their own admin-approved sender email and provider credential privately in the screen. Passwords are encrypted in the database through the key service, never returned by the API. From and Reply-To equal that staff email. Changing host/port/TLS mode invalidates saved credential binding until staff re-enter the password. No real staff password was supplied as part of this configuration task and live SMTP authentication remains unverified.

Environment variables still control infrastructure and MAIL_DELIVERY_MODE. Synthetic development capture does not send real email. With SMTP selected, workers require enabled organisation settings and a configured owning staff credential; legacy shared EMAIL_HOST_PASSWORD / provider profiles are not a delivery fallback. Secret rotation must happen at the provider; changing application settings alone cannot revoke an old credential. Never put custody keys or staff SMTP passwords into tracked files or VITE_* settings.

## Docker Compose

Compose reads the root file for variable substitution; it does not automatically
forward every key to containers. The explicit `compose.yaml` environment still
controls container settings, including synthetic captured mail. Run
`python scripts/init_compose.py` to fill a missing/blank `POSTGRES_PASSWORD`
without replacing other settings or an existing database credential. Changing
an environment password does not rotate an initialized PostgreSQL account.

Keep backend secrets out of frontend `VITE_*` variables: those can be included
in browser assets. This root file is loaded by Django, not exposed as an asset.


## Explicit operator capabilities and staged storage

SETUP_TOKEN_SHA256 and DEV_INBOX_TOKEN_SHA256 are blank by default in root .env. Configure separate SHA-256 digests of high-entropy random operator tokens; blank disables the corresponding access. Bootstrap consumes its capability when the first staff account is created. The development inbox takes its separate capability through X-Dev-Inbox-Token (the UI has an unlock form); it is never stored in browser persistent storage. See P2_REMEDIATION.md for custody and API details. STAGED_UPLOAD_QUOTA_BYTES defaults to 104857600 for each staff account or recipient grant; committed submissions do not count toward this staged budget.

Provider correction, 31 October 2026: the user confirmed IONOS hosts the mailbox. The organisation transport now uses smtp.ionos.com:587 STARTTLS. Live EHLO/STARTTLS/post-TLS EHLO succeeded. Staff must re-enter their mailbox password after this transport change; authentication and delivery remain unverified. Google App Password guidance does not apply to this IONOS Mail configuration.

## Local evidence preservation and OTP sender update — 31 October 2026

See [EVIDENCE_ARCHIVE.md](EVIDENCE_ARCHIVE.md) for the implemented capture catalog, original-file hashes, server-download provenance, encrypted create-only local bundles, verified exports, legacy backfill and optional RFC 3161 verification. The user selected local preservation for now and an unset TSA. Deployment must not silently switch to AWS. Local preservation is not administrator-proof cloud WORM; pending timestamps are not trusted timestamps. Hospital-list reconciliation is excluded.

Emailed recipient OTP challenges authenticate through the organisation SMTP transport using the conversation owner's encrypted staff SMTP username and password. Only the From/envelope sender is support@onesmarter.com; Reply-To remains the staff address. No separate support password is required. The provider must authorize each staff account to send as support@onesmarter.com; rejected delivery fails closed without a sender fallback. Missing staff credentials block OTP delivery. Staff authenticator TOTP is unchanged. Ordinary conversation notifications retain each owning staff member's SMTP sender.

Local key-service calls now prefer the IPv4 loopback listener while retaining localhost certificate verification and PQ requirements. Every wrap/unwrap still contacts the service; no plaintext, data keys or readiness result is cached to achieve the speedup. Initial workspace session checks time out after eight seconds with retry; authenticated drafts survive transient polling failures.
