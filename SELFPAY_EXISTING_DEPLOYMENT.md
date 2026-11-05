# Update the existing SelfPay integration

This is an update to an existing deployment, not a new installation.

## Reported EC2 state

- Secure Mail: `/var/www/securemail-backend/current`, environment
  `/etc/onesmarter/backend.env`, separate custodian-controlled key service.
- SelfPay web and booking worker currently use
  `/var/www/MyselfPay_Backend-integration` and
  `/var/www/MyselfPay_Backend-integration-venv`.
- Original SelfPay checkout: `/var/www/MyselfPay_Backend`. Do not delete the
  integration checkout while either service uses it. A worktree is a release
  staging directory, not a second application or database.
- SelfPay database: local PostgreSQL `newselfpaydb`; migration 0010 applied.
- Existing test booking is retrying. Preserve its request ID for idempotent retry.
- Database backup reported at `/var/backups/selfpay-pre-integration.8yU19w`.
  Archive listing passed; a clean-machine restore has not been demonstrated.

These facts came from operator output, not direct access to EC2. Confirm service
WorkingDirectory and ExecStart before deploying. Do not expose Environment values.

## Required release order

1. Back up both current databases and protected environment files again before
   this release. Preserve DATABASE_URL, Django secrets, BOOKING_ENCRYPTION_KEY,
   integration HMAC secret, mTLS identity and the original unseal key.
2. Pause only `myselfpay-booking-chat.service` during the coordinated update.
   Drain/pause SelfPay web writes while replacing code and applying its migration.
   Do not stop shared nginx, PostgreSQL or the key service.
3. Deploy Secure Mail backend with environment-SMTP notifications and private
   portal messages; apply core migration `0026_portal_private_system_messages`
   using `/etc/onesmarter/backend.env`. Restart Secure Mail API/outbox processes.
4. Deploy Secure Mail frontend with private confirmation/action rendering.
5. Update the actual active SelfPay checkout with the private-confirmation
   outbox changes; apply `api.0011_booking_chat_events` with its existing `.env`.
   Do not run the SQL file separately. Restart the existing SelfPay API and worker.
6. Keep the integration enabled on both sides, owner active/MFA-confirmed,
   provider notifications unsuppressed, and approved action origin set to
   `https://myselfpay.onesmarter.com`. Secure Mail SMTP must authorize sending as
   `support@onesmarter.com`; SelfPay does not receive those SMTP credentials.
7. Verify the existing retrying request before creating more test bookings.
   Initial booking details and clinic action are provider-only. Confirmation and
   patient tracking action are requester-only. Normal replies remain shared.
   Notifications contain no booking details; portal access requires email OTP.

Updating a checkout does not update an already-running Python process. Both
SelfPay services must use the same code and environment. Keep the old checkout
and venv until verification succeeds; do not reverse migrations as a routine
code rollback. The confirmation migration's reverse operation does not remove
its table. Pending events need compatible workers after any rollback.

## Retry diagnostics

The updated SelfPay worker logs `secure_mail_handoff`, an operation, fixed error
category, and HTTP status. No response body, URL, booking payload, secret or raw
exception text is logged. Read with:

```bash
journalctl -u myselfpay-booking-chat.service --since '10 minutes ago' --no-pager
```

`http_rejected` requires checking the corresponding HTTP status and Secure Mail
API logs; `tls_failed` requires certificate/trust checks; `timeout` or
`connection_failed` requires connectivity checks. Configuration/response errors
are deliberately grouped to avoid leaking sensitive exception text.

Never bypass mTLS, HMAC, OTP, TLS policy or key-service readiness to clear retry.
TLS 1.3 and HTTP 404 at `/` prove connectivity only, not signed booking delivery.
Local tests do not establish AWS deployment, live SMTP delivery or independent
cryptographic approval.
