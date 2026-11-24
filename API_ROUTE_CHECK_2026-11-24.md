# API v1 route verification — 2026-11-24

Scope: all 11 method/path combinations authenticated by API keys in v1.
Live target: https://securemailbackend.onesmarter.com/api/v1.
No API secrets, OTPs or recipient addresses are stored in this report.

| Method | Route | Live result | Coverage limit |
|---|---|---|---|
| GET | /status | 200, ready=true | Current readiness only |
| POST | /messages | 201 in immediately preceding live test | One authorized synthetic notification; SMTP provider accepted |
| GET | /messages | 200 | Calling test key only |
| GET | /messages/{id} | 200 | Synthetic message; protected=true, reply=false |
| POST | /templates/preview | 200 | No email or challenge sent |
| POST | /templates | 201 | One synthetic template stored |
| GET | /templates | 200 | Calling test key only |
| GET | /templates/{id} | 200 | Newly created synthetic template |
| POST | /bookings | 400 for empty payload | Live rejection only; no appointment created |
| GET | /bookings/{id} | 404 for nonexistent UUID | Live rejection only |
| POST | /bookings/{id}/confirmation | 404 for nonexistent UUID | No approval recorded |

Focused local regression command: pytest backend/tests/test_api_keys.py
backend/tests/test_api_bookings.py backend/tests/test_api_presentation.py
backend/tests/test_api_recipient_inbox.py -q.
Result: **42 passed in 7.68 seconds** using synthetic settings and isolated database.
Tests cover booking create/read/confirmation and idempotency, key/owner isolation,
invalid origins and recipients, profile eligibility, custom markup restrictions,
OTP binding, recipient authorization, reply policy, CSRF, key lifecycle and limits.
This does not prove production PostgreSQL concurrency or successful live booking
approval/OTP delivery. The recipient browser flow remains user-verifiable.

## Profile findings

- Notification profile controls message notification/OTP design and delivery.
  Scopes separately authorize routes.
- Booking scopes can belong to a standard-profile key issued to the configured
  SelfPay owner. Booking routes themselves always use SelfPay rules and branding.
- SelfPay-profile message sends reject template_id. Template preview/create/read
  endpoints themselves are not profile-restricted; stored templates cannot be
  applied to SelfPay-profile messages.
- /messages is not a clinic-only endpoint, even with the SelfPay profile. Callers
  choose its recipient. /bookings enforces clinic-only, read-only behavior.
- /bookings/{id}/confirmation records an assertion from a trusted API caller.
  It does not independently approve or query a booking in the SelfPay database.

## Side effects and delivery status

This route-check run stored one synthetic template. It sent no additional email,
created no booking, and recorded no approval. The preceding authorized message
send queued one notification that the SMTP provider accepted; inbox placement is
not established by provider acceptance. No production configuration was changed.
The two profile guides and this report are local documentation changes, not an
AWS or Vercel deployment.
