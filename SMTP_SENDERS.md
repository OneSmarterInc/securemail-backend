# Approved SMTP sender identities

> Notification sender update (2026-11-05): OTPs, staff/recipient invitations, and protected-message notifications (including SelfPay) send as `OneSmarter Support <support@onesmarter.com>` using backend environment `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_USE_TLS` and `EMAIL_USE_SSL`. They do not require personal SMTP credentials or an OrganizationSMTP row. The provider must authorize the configured account to send as support@onesmarter.com. Ordinary Nophi email retains approved personal SMTP credentials. Custody readiness checks remain mandatory. This supersedes earlier owner-credential instructions for notifications.

Updated 29 October 2026. Production provider/mailbox approval remains pending.

Application delivery now requires an exact mapping for every From address.
Notifications use DEFAULT_FROM_EMAIL; ordinary mail uses the conversation sender
and rechecks the actor's current sender grants. Both must use the exact company
domain. Missing mapping, missing credentials, an unrelated domain or revoked
sender authority fails with sender_not_configured before opening SMTP. There is
no fallback to the global EMAIL_HOST_USER credential and no From rewriting.
The synthetic captured-mail adapter does not contact a provider.

## Configuration

1. Provision the chosen company-domain mailbox/aliases with the selected provider.
2. Verify provider authorization for each exact address and its domain's SPF/DKIM
   configuration. A mapping is operator approval, not automatic DNS verification.
3. Copy deploy/smtp-senders.example.json to .runtime/smtp-senders.json and replace
   every placeholder. Map each address to its host, port, username, security mode
   and dedicated password environment-variable name. The mapping supports
   starttls or implicit tls; plaintext SMTP is rejected. There are no wildcards.
4. Set SMTP_SENDER_PROFILES_FILE to that private mapping and DEFAULT_FROM_EMAIL
   to the approved company notification address in the root .env. Populate the
   referenced SMTP_PASSWORD_* variables locally; never put secrets in the tracked
   example. Existing process variables override the root file.
5. Restart API/worker, then run approved mailbox tests. Failed queued jobs require
   the existing explicit retry workflow; changing configuration does not silently
   replay them.

The mapping can point multiple approved aliases to one credential only when the
provider explicitly authorizes those aliases. It is not permission to impersonate
all staff. Account creation or granting a sender in the portal does not provision
a provider mailbox or its credential mapping.

## Release evidence

The earlier claim that particular DNS records necessarily cause every message to
fail DMARC is not verified here. DMARC alignment depends on the actual envelope
sender, visible From and authenticated SPF/DKIM results. Capture received-message
Authentication-Results for controlled test recipients and verify alignment for
notifications and ordinary mail separately. Do not infer inbox delivery from SMTP
acceptance. Approve sender identity, bounce handling and public portal-link domain.

Private Email's info@kormic.ai profile previously passed an explicit SMTP test;
it is not an approved OneSmarter application sender. Global EMAIL_HOST_* settings
remain available for explicitly authorized diagnostic sends but do not authorize
queued application delivery. Until company-domain mappings are provisioned, real
application mail fails closed. The Connections page reports this configuration
state without exposing credentials. This does not remove any production gate.
