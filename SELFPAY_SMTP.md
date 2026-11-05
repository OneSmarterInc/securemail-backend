# Dedicated SMTP for SelfPay mail sent by Secure Mail

Set these in `/etc/onesmarter/backend.env`. Enter the real mailbox password on the
server, never in a repository or frontend environment.

```dotenv
SELFPAY_SMTP_ENABLED=true
SELFPAY_EMAIL_HOST=smtp.ionos.com
SELFPAY_EMAIL_PORT=587
SELFPAY_EMAIL_HOST_USER=patientcare@onesmarterhealthweb.com
SELFPAY_EMAIL_HOST_PASSWORD='REPLACE_ON_SERVER'
SELFPAY_EMAIL_USE_TLS=true
SELFPAY_EMAIL_USE_SSL=false
SELFPAY_FROM_EMAIL=patientcare@onesmarterhealthweb.com
```

From and Reply-To both use SELFPAY_FROM_EMAIL. SMTP login uses the full mailbox
address. IONOS documents `smtp.ionos.com`, port 587 with STARTTLS (or 465 with
SSL/TLS): https://www.ionos.com/help/email/general-topics/ionos-mail-server-details-for-imap-pop3-and-smtp/

Scope: initial patient and clinic invitations, secure-portal OTPs, approval
notifications and message notifications belonging to the `selfpay` integration.
The worker resolves the source from the organization-scoped thread, or the
encrypted OTP payload's source and the challenge mailbox's active memberships.
Older queued OTPs without a source use the mailbox's sole active integration if
unambiguous; mixed-source legacy OTPs retain the general route and expire normally.

No source is inferred from a subject line or recipient email domain. All existing
suppression, revocation, expiry, authorization and sealed-service checks remain.
When enabled, invalid dedicated SMTP settings fail with `sender_not_configured`;
they never fall back to the general SMTP account. Disabled by default for backward
compatibility. Enable explicitly when deploying these settings. Valid queued jobs
pick up the current transport at send time; already delivered mail is not resent.
Failed jobs still require the existing retry flow after correcting configuration.

General EMAIL_* settings continue to serve other system mail. Ordinary staff mail
retains its authorized staff SMTP transport. SelfPay's own patient verification and
clinic approval OTPs are sent by the SelfPay backend, so they are outside this
Secure Mail SMTP change; do not alter SelfPay's .env for this release.

No migration, certificate update, frontend release or key-service restart is
required. Preserve the existing .env and unseal key. Deploy the new backend release,
validate with the environment loaded, and restart onesmarter-api, onesmarter-worker
and onesmarter-beat only. Workers may send eligible queued mail after restart.

An SMTP connection/authentication check does not prove inbox delivery. Verify a
new fictional booking, both initial invitations, portal OTP, reply and approval
notification in mailboxes you control. Confirm From and Reply-To in the received
headers. Do not expose passwords or OTPs in test output.
