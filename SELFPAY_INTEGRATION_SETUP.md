# SelfPay integration using the existing Secure Mail domain

> Notification sender update (2026-11-05): OTPs, staff/recipient invitations, and protected-message notifications (including SelfPay) send as `OneSmarter Support <support@onesmarter.com>` using backend environment `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_USE_TLS` and `EMAIL_USE_SSL`. They do not require personal SMTP credentials or an OrganizationSMTP row. The provider must authorize the configured account to send as support@onesmarter.com. Ordinary Nophi email retains approved personal SMTP credentials. Custody readiness checks remain mandatory. This supersedes earlier owner-credential instructions for notifications.

No new DNS record or integration hostname is needed. These instructions use:
- API: `https://securemailbackend.onesmarter.com`
- Recipient portal: `https://securemail.onesmarter.com`
- SelfPay: `https://myselfpay.onesmarter.com` (replace if your deployed origin differs).

## 1. Prepare Secure Mail

SelfPay integration prerequisite: merge and deploy [backend PR #2](https://github.com/OneSmarterInc/MyselfPay_Backend/pull/2) and the matching SelfPay frontend integration before enabling these settings. At preparation time, the adapter and migration were on `codex/selfpay-secure-mail-integration`, not `main`. Environment changes alone cannot add missing code.

Back up the database and apply reviewed pending Django migrations in both applications before enabling the integration. Secure Mail needs the portal migration `0024_integrationnonce_portalmailbox_portalchallenge_and_more`; SelfPay needs `0010_booking_chat`. Follow any deployment-specific database approval policy. Do not run old standalone SQL over a migrated Django schema.

Choose an active, MFA-confirmed Secure Mail owner in the intended organisation. Find its ID from the backend application environment:

```bash
python manage.py shell -c "from backend.apps.core.models import StaffUser; print(list(StaffUser.objects.filter(is_active=True,status='active',mfa_confirmed=True).values('id','email')))"
```

Confirm the key service is unsealed and the owner's SMTP transport is authorised to send integration notifications and OTPs from `support@onesmarter.com`. Keep the normal Secure Mail outbox worker and scheduler running.

## 2. Provision integration certificates

Use a dedicated integration-client CA to issue SelfPay a client certificate with `clientAuth` extended key usage. Keep the CA signing private key off the application hosts. Install:

| Host | File | Purpose |
| --- | --- | --- |
| Secure Mail nginx | `/etc/onesmarter/pki/selfpay-client-ca.pem` | Public CA chain that verifies the SelfPay client |
| SelfPay backend | `/etc/selfpay/pki/integration-client.pem` | Client certificate and intermediate chain |
| SelfPay backend | `/etc/selfpay/pki/integration-client.key` | Client private key; readable only by the SelfPay service identity |

This is separate from the HTTPS server certificate already installed for `securemailbackend.onesmarter.com`. Never copy the key-service workload or custodian private keys into SelfPay. Plan certificate renewal/revocation before expiry.

The existing API uses TLS 1.3 with `X25519MLKEM768`. SelfPay's Python/OpenSSL runtime must support that negotiated group (OpenSSL 3.5+ with support enabled); check the actual runtime with `python -c "import ssl; print(ssl.OPENSSL_VERSION)"` and verify the handshake. Version alone is not proof of negotiated PQ transport. Do not silently downgrade the API policy.

## 3. Update the existing nginx API server

Merge `deploy/aws-api.nginx.conf.example` from securemail-backend into the existing API server block. Do not add a second block for the same hostname. Install the client CA before applying this template; nginx cannot load it if the file is absent.

The server uses `ssl_verify_client optional`: ordinary browser calls require no client certificate. The exact `/api/integrations/threads` location requires `$ssl_client_verify = SUCCESS`, permits only POST, rejects query strings, limits bodies to 32 KiB and strips browser cookies. The application still checks the HMAC signature, timestamp, nonce, owner and idempotency reference. A client certificate alone does not authorise a booking.

Validate and reload using the nginx binary/service installed by your deployment:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Keep Gunicorn on its Unix socket. Do not expose another public backend port that bypasses nginx. No change to key-service port 8443, private DNS or public DNS is needed.

## 4. Set the Secure Mail backend environment

Generate an independent random integration secret (at least 32 characters) in your secret-management workflow. Put the SAME value in both backends. Do not use an SMTP password, Django SECRET_KEY or root recovery key.

In the protected backend environment file, add one JSON line, replacing owner ID, secret and the actual SelfPay origin:

```dotenv
SECURE_MAIL_INTEGRATIONS='{"selfpay":{"enabled":true,"name":"MySelfPay","owner_id":123,"secret":"REPLACE_WITH_INDEPENDENT_RANDOM_SECRET","suppress_provider_notifications":false,"provider_action_origins":["https://myselfpay.onesmarter.com"]}}'
RECIPIENT_PUBLIC_URL=https://securemail.onesmarter.com/recipient
```

Use the quoting format supported by your environment loader. Retain existing integration entries if there are any. The API hostname must already be in `ALLOWED_HOSTS`. Restart the backend and its workers with the updated environment.

## 5. Set the SelfPay BACKEND environment

```dotenv
SECURE_MAIL_ENABLED=true
SECURE_MAIL_URL=https://securemailbackend.onesmarter.com
SECURE_MAIL_PORTAL_URL=https://securemail.onesmarter.com
SECURE_MAIL_KEY_ID=selfpay
SECURE_MAIL_SECRET=REPLACE_WITH_THE_SAME_INDEPENDENT_RANDOM_SECRET
SECURE_MAIL_ALLOW_LOOPBACK_HTTP=false
SECURE_MAIL_CLIENT_CERT=/etc/selfpay/pki/integration-client.pem
SECURE_MAIL_CLIENT_KEY=/etc/selfpay/pki/integration-client.key
```

`SECURE_MAIL_URL` is the API origin, with no `/api` suffix. The adapter adds `/api/integrations/threads`. `SECURE_MAIL_PORTAL_URL` is the recipient origin, with no `/recipient` suffix. For a publicly trusted server certificate, leave `SECURE_MAIL_CA_FILE` unset so system trust is used. For a private server CA, set it to the server CA bundle on SelfPay; this is NOT the integration-client CA merely because their names look similar.

Restart SelfPay's backend and run this existing command as a supervised service with the same backend environment and service account:

```bash
python manage.py process_booking_chats --watch
```

Do not also start the legacy standalone `booking_chat.py` worker. No integration secret or client private key belongs in either frontend, a `VITE_` variable, GitHub, or browser storage. This backend-to-backend handoff needs no browser CORS exception.

## 6. Verify the complete flow

1. Confirm normal staff login and recipient OTP still work without a client certificate.
2. A POST to the integration endpoint without a client certificate must return 403. With a trusted certificate but invalid/missing signed headers, it must also fail at application authentication.
3. Submit a new test booking through SelfPay after verifying the test patient's email. Use approved test patient and clinic mailboxes. This sends real notifications when SMTP is enabled.
4. Confirm the booking persists, its chat state becomes ready, and exactly one Secure Mail thread exists for that booking reference. Reprocessing the same booking must not duplicate it.
5. Open the portal as each participant, verify OTP and exchange replies. Confirm the clinic-only confirmation action is absent for the patient.
6. Temporarily stop the handoff worker in staging: bookings must remain saved/pending. Restart it and confirm the backlog drains without duplicate threads.

No old bookings are automatically backfilled. If a handoff stays pending, check worker status, TLS negotiation, client certificate trust/expiry, matching key ID/secret, clock synchronisation, active owner and key-service availability. Do not log patient content or secrets while investigating.

## Evidence boundary

The nginx regression test exercises the shipped shared-host routing with real client certificates on stock nginx. It substitutes classical X25519 only inside the test fixture, so it does not prove deployed PQ negotiation. Production DNS, certificates, SMTP, migrations and end-to-end handoff must still be verified on the deployed hosts. Existing release gates remain in force.
