# SelfPay and OneSmarter Secure Mail

SelfPay remains independently deployed. It owns the booking and its patient-email verification. Secure Mail owns the shared partner inbox, email OTP sessions, encrypted chat content, replies, search and unread state. There is no shared database, browser authentication cookie, or copy of Secure Mail's chat implementation in SelfPay.

## Booking handoff

1. The patient verifies their email and submits an appointment request in SelfPay.
2. After the verified patient submits the request, SelfPay records a `booking_chat` row in the same booking transaction. Direct clinic request emails are suppressed while this integration is enabled. The clinic address comes exclusively from the approved server catalog; the patient address comes from the verified email proof.
3. After commit, SelfPay signs an HTTPS request to `POST /api/integrations/threads`. The request contains the booking reference, patient name/phone, requested exam and three preferred windows, and the two participant addresses. The provider confirmation URL is transferred separately as `provider_action: {url, expires_at}`. It is encrypted in thread metadata, excluded from email notifications and exposed only to the verified provider participant. Patient tracking tokens are not transferred.
4. Secure Mail creates one encrypted thread, its participants, and generic notifications for both participants in a transaction. `(integration key ID, booking reference)` makes retries idempotent. Changed content under the same reference is rejected.
5. SelfPay exposes the secure conversation link on patient and clinic dashboard requests before approval. The URL contains only a thread ID and integration identifier. Neither identifies a logged-in user nor grants access. Both parties must verify their own mailbox in Secure Mail.

If Secure Mail is unavailable, the booking remains saved. The receipt shows that the chat is being prepared. A durable worker retries after 60 seconds. A crashed worker's lease expires after two minutes. Run the retry worker regularly; receipt polling does not initiate network writes.

Clinics with no approved scheduling email receive no chat handoff. Their receipt explains that secure chat is unavailable. Do not substitute a guessed address or a browser-provided email.

## Testing mode and notifications

For submitted SelfPay bookings, configure `suppress_provider_notifications: false`. Secure Mail queues initial invitations for both participants and emails the other participant after a reply. Portal invitations, reply notifications and OTPs use `support@onesmarter.com` with the existing authorized SMTP transport. SelfPay patient/clinic verification mail uses its separately configured SMTP service.

The default `suppress_provider_notifications: true` remains available for isolated testing. Suppression is captured on each participant and rechecked at delivery time. Enabling delivery does not replay existing suppressed invitations. Tests use synthetic mail; no external messages are sent by test suites.

## Configuration and rollout

Deploy and test the Secure Mail change before setting `SECURE_MAIL_URL` in SelfPay. Enable `SECURE_MAIL_ENABLED=true` only after configuring both services. It defaults to false.

SelfPay service environment:

```dotenv
SECURE_MAIL_ENABLED=true
SECURE_MAIL_URL=https://integration.example.com
SECURE_MAIL_PORTAL_URL=https://secure-mail.example.com
SECURE_MAIL_KEY_ID=selfpay
SECURE_MAIL_SECRET=<independent random secret of at least 32 characters>
SECURE_MAIL_ALLOW_LOOPBACK_HTTP=false
SECURE_MAIL_CLIENT_CERT=/run/secrets/selfpay-client.crt
SECURE_MAIL_CLIENT_KEY=/run/secrets/selfpay-client.key
SECURE_MAIL_CA_FILE=/run/secrets/integration-ca.crt
```

Secure Mail uses a server-only `SECURE_MAIL_INTEGRATIONS` JSON mapping:

```json
{
  "selfpay": {
    "enabled": true,
    "name": "MySelfPay",
    "owner_id": 123,
    "secret": "<same independent service secret>",
    "suppress_provider_notifications": false,
    "provider_action_origins": ["https://selfpay.example.com"]
  }
}
```

Use an existing active, MFA-confirmed service owner with the correct organization and working Secure Mail SMTP/OTP credentials. The integration does not create an administrator or expose staff privileges to patients. Configure `PUBLIC_URL`, trusted origins, HTTPS proxy handling, cookie security, the existing encryption/key service and outbox mail worker as documented by Secure Mail. Keep all secrets in deployment secret storage or an access-restricted environment file. Do not put the JSON secret in frontend build variables, logs or version control.

For the existing split staff/recipient ingress, use the staged `deploy/integration-nginx.conf.example` as a separately reviewed workload hostname. It accepts only the signed thread-creation endpoint, requires client-certificate authentication and TLS 1.3, and exposes no browser API. Add the workload hostname to Django's `ALLOWED_HOSTS`; trust forwarded HTTPS only from the configured private proxy/socket. Keep staff PQ transport policy intact. The Python adapter supports a private CA and a client certificate/key; it always verifies the server certificate/hostname. `SECURE_MAIL_PORTAL_URL` is the recipient **origin**, while Secure Mail's `RECIPIENT_PUBLIC_URL` includes `/recipient`. These values must refer to the same recipient host. Set both origins explicitly for local tests; loopback HTTP requires the development-only flag.

Secure Mail currently documents existing production release gates in `DEPLOYMENT.md` and `RELEASE_GATES.md`. This integration does not waive or bypass those gates. No public production enablement is implied by a successful local run.

The new MySelfPay backend needs Django migration `0010_booking_chat` (SQL: `ops/booking-chat.sql`). Run `python manage.py process_booking_chats --watch` as a supervised worker. Secure Mail also needs its normal outbox delivery worker. **Live Neon SQL requires the approved change record, committed SQL SHA, branch-copy test and backup specified in `ops/change-records/POLICY.md`.** This work does not execute live SQL.

Secure Mail adds Django migration `0024_integrationnonce_portalmailbox_portalchallenge_and_more`, after the concurrent `0023_message_history_index` change. Apply it under that deployment's normal reviewed migration/backup process before enabling the integration. Its schema is separate from SelfPay's schema.

Schedule this command at least once per minute under SelfPay's service identity and environment:

```bash
/var/www/SelfPay/.venv/bin/python /var/www/SelfPay/booking_chat.py --maximum 25
```

It reads `BOOKING_DATABASE` or `DATABASE_URL`. For local SQLite, provide `--database /absolute/path/to/review.sqlite3`. It prints only the number of completed handoffs, never patient details. Monitor pending row age/attempts through an approved operational process. Handoffs stop retrying only on success, booking retention cleanup, or an explicitly reviewed operator action; invalid credentials therefore stay pending until repaired.

## Security and lifecycle

- HMAC-SHA256 binds method, exact path, integration ID, timestamp, random nonce and body hash. Five-minute clock skew allowance and unique stored nonces prevent replay. TLS is mandatory in production; explicit loopback HTTP is available only for local development. No redirects are followed by the SelfPay client.
- Mailbox sessions use Secure Mail's existing HttpOnly, same-origin recipient cookie boundary and CSRF enforcement. OTP challenges bind to the requesting browser, expire after ten minutes, allow five guesses, and can be consumed once. Resends have a 60-second cooldown, plus IP/mailbox budgets.
- Sessions expire after 15 minutes idle or eight hours absolute. Background reads never prolong them. Every inbox, thread and reply rechecks mailbox participation, organization and revocation. Links alone and staff cookies do not grant inbox access.
- Content, names and email addresses reuse Secure Mail envelope encryption and its key-management/custody migration machinery. Authorized server processes can decrypt; this is **not end-to-end encryption**. Audit records contain identifiers/actions, not message bodies or search terms.
- Search scans at most 100 authorized encrypted thread summaries per request, with continuation. This avoids storing plaintext names/subjects in a search index; very large mailboxes may require multiple search pages.
- Chat content follows Secure Mail's existing retained-conversation policy. Deleting a SelfPay booking after its retention period does not delete the separate Secure Mail conversation. Agree a shared retention/deletion policy before processing real patient data.
- This first adapter supports two-party text conversations. Attachments, booking-status synchronization, historic booking backfill and administrative mailbox reassignment are separate changes.

## Future integrations

Register each future project with a distinct integration ID, secret and authorized owner. Reuse `/api/integrations/threads`, the same portal and the existing services. Each caller provides an immutable external reference, subject, body and exactly one `requester` and one `provider` participant. Additional participant roles or group sharing need an explicit authorization design, not an unvalidated extra recipient field.

## Validation limits

Tests use disposable SQLite databases and synthetic mailboxes, including real loopback HTTP and browser access. Production SMTP delivery, production TLS/proxy behavior, PostgreSQL concurrency and deployment migrations require staging validation. Passing these tests is not a claim of a complete security audit or production compliance certification.

The clinic-only action links back to the existing SelfPay clinic verification/approval flow. The URL origin must match provider_action_origins exactly, and expired actions are omitted. Patients never receive this action in API responses or notifications. This change needs no schema migration beyond the existing portal migration.
