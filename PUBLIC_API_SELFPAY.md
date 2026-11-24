# SelfPay / Patient Care — API guide

Choose this profile for explicitly added SelfPay message triggers using the
established Patient Care notification and OTP templates and configured SelfPay
SMTP. Internal profile value: `selfpay`. Only the configured, enabled SelfPay
owner can use this profile. Existing HMAC integration triggers remain unchanged.

Production base URL: `https://securemailbackend.onesmarter.com/api/v1`.
Use a server-side Bearer key; never put it in Vite/browser code or a URL.
For an interactive Bash test, enter it without adding the value to shell history:

```bash
read -rsp 'API key: ' SECUREMAIL_API_KEY; printf '\n'
export SECUREMAIL_API_KEY
export SECUREMAIL_BASE_URL='https://securemailbackend.onesmarter.com/api/v1'
```

Create the key at **Access > API keys**. Save its secret once; select only needed
permissions. Key creation/revocation requires administrator privileges and fresh MFA.
Do not share the key with recipients. Revoke test keys after testing.

A **profile** selects branding and delivery configuration. A **permission/scope**
authorizes an API operation. Selecting a profile alone does not grant permissions,
create an appointment, send mail, or enable an existing integration.

## Routes and profile behavior

| Method | Path | Permission | Behavior |
|---|---|---|---|
| GET | /status | status:read | Service readiness |
| POST | /messages | messages:write | Protected message with SelfPay notification/OTP |
| GET | /messages | messages:read | This key's ordinary message streams |
| GET | /messages/{id} | messages:read | Protected content and delivery status |
| POST | /bookings | bookings:write | Clinic-only request and SelfPay action link |
| GET | /bookings/{id} | bookings:read | This key's booking status |
| POST | /bookings/{id}/confirmation | bookings:write | Record completed SelfPay approval |
| POST | /templates/preview | messages:write | Preview only; not used by SelfPay sends |
| POST | /templates | messages:write | Storage supported, but cannot attach to SelfPay sends |
| GET | /templates | messages:read | This key's stored templates |
| GET | /templates/{id} | messages:read | This key's stored template |

**Custom template_id is rejected on SelfPay message sends.** Template routes
currently have no profile restriction, but creating a template does not override
the fixed SelfPay designs. Use a separate Secure Mail profile key for customization.

**Profile does not enforce clinic-only recipients on /messages.** That endpoint
accepts the supplied single recipient and defaults reply=false; explicit true
can enable replies. Your SelfPay caller must supply only the intended clinic.
For the enforced clinic-only, always read-only appointment workflow, use /bookings.
Booking routes require the configured SelfPay owner and an enabled integration,
regardless of the key's selected notification profile.

Never invoke both the existing HMAC trigger and the new API method for the same
intended notification. Creating an API key does not switch any existing trigger.

## Quick start: curl

Set `SECUREMAIL_API_KEY` securely in your server environment first.

```bash
export SECUREMAIL_BASE_URL='https://securemailbackend.onesmarter.com/api/v1'

curl --fail-with-body "$SECUREMAIL_BASE_URL/status" \
  -H "Authorization: Bearer $SECUREMAIL_API_KEY"
```

Response:

```json
{"ready": true, "api_version": "v1"}
```

A 200 response with `ready: false` means authentication succeeded but protected
messaging is unavailable. Sending/reading messages then returns 503.

## Send a protected message

```bash
curl --fail-with-body "$SECUREMAIL_BASE_URL/messages" \
  -H "Authorization: Bearer $SECUREMAIL_API_KEY" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: booking-123-notification-1' \
  --data '{
    "sender": "authorized-staff@onesmarter.com",
    "to": "recipient@example.com",
    "subject": "Your secure information",
    "body": "Please review the information in this protected message.",
    "reply": false
  }'
```

`sender` must be a company address authorized on the administrator who created
this key. The example address is a placeholder. Notification delivery uses the
existing approved Secure Mail SMTP configuration; this field does not bypass
SMTP provider sender authorization.

| Field | Requirements |
|---|---|
| `sender` | Authorized email, at most 254 characters |
| `to` | One recipient email, at most 254 characters |
| `subject` | Nonempty, at most 180 characters; no CR/LF |
| `body` | Nonempty text, at most 100,000 characters |
| `template_id` | Optional UUID of a notification template created with this same API key |
| `reply` | Optional JSON boolean; defaults to false. Only explicit true enables recipient replies |

Unknown fields are rejected. HTML is not an executable email template.
A new request returns HTTP 201 with `{"id":"conversation-uuid"}`. The message is
encrypted in storage and a recipient verification invitation is queued. HTTP 201
means accepted by Secure Mail, not delivered to the recipient's inbox.

`Idempotency-Key` is required, 1–100 characters. Reusing it with the same body and
same API key returns HTTP 200 with the existing ID, without another invitation.
Reusing it with different data returns 409. Retain the same key on network retries.

## Read messages and delivery status

```bash
curl --fail-with-body "$SECUREMAIL_BASE_URL/messages?page=1&page_size=25" \
  -H "Authorization: Bearer $SECUREMAIL_API_KEY"

curl --fail-with-body "$SECUREMAIL_BASE_URL/messages/CONVERSATION_UUID" \
  -H "Authorization: Bearer $SECUREMAIL_API_KEY"
```

List responses contain `results`, `count`, `page`, and `page_size`. Page sizes are
25, 50 or 100. Sort with `sort=created_at` or `sort=-created_at` (default).
Summary fields: `id`, `state`, `protected`, `created_at`, `revoked`.
Summary also includes the current `reply` policy. Detail returns the most recent
100 messages in chronological order and `messages_truncated` if older messages
exist. The recipient portal retains its existing older-message pagination.
Detail adds the decrypted `subject`, up to the first 100 `messages` (each has
`id`, `body`, `created_at`, `sender_type`), and the newest 20 delivery outcomes
(`state`, `error_code`). This bounded v1 detail endpoint is intended for short
exchanges; use the staff portal for longer histories.

`provider_accepted` means the SMTP provider accepted delivery, not that the email
was read or reached an inbox. Failed delivery is reported by its error code.

## Python example (standard library)

```python
import json
import os
import urllib.request

base = os.environ['SECUREMAIL_BASE_URL'].rstrip('/')
key = os.environ['SECUREMAIL_API_KEY']
request = urllib.request.Request(
    base + '/status', headers={'Authorization': 'Bearer ' + key}
)
with urllib.request.urlopen(request, timeout=15) as response:
    print(json.load(response))
```

Use server-side HTTPS libraries with certificate verification enabled. Do not
forward Authorization headers across redirects or log request headers.

## Errors and retries

Errors use `{"error":{"message":"...","code":"..."}}`.

| HTTP status | Meaning / action |
|---|---|
| 400 | Invalid fields, unsupported pagination, or missing idempotency key |
| 401 | Missing, invalid, expired, revoked or disabled API credential |
| 403 | Missing scope, unauthorized sender, or HTTPS required |
| 404 | Message is absent or belongs to another key |
| 409 | Idempotency key reused with a changed request |
| 429 | Rate limited; honor the `Retry-After` response header |
| 503 | Key service or another required service is unavailable |

Each key has a token-bucket budget of 60 requests per minute. Authentication also
has an IP budget of 120 per minute. Bursts consume tokens; they refill over time.
Retry 429/temporary 503 with bounded exponential backoff and jitter. Reuse the
same idempotency key and body for POST retries. Never retry permanent 4xx blindly.

## Isolation, expiry and revocation

- A key can read only messages created with that exact key, even if another key
  belongs to the same administrator or organization. Unrelated staff and partner
  conversations remain inaccessible.
- Deactivation, loss of MFA, admin/privilege removal or a session-version change
  on the owner disables the key. Key expiry and explicit revocation are checked
  on every request.
- Revocation stops future requests. An in-flight transaction may finish before
  revocation completes. Revocation does not delete messages, revoke recipient
  access or cancel already queued emails.
- Rotate by creating a replacement, updating your integration, then revoking the
  old key. The replacement cannot read the old key's conversations; retain staff
  portal access to history. There is no secret-reveal or restore endpoint.
- Lifecycle events and successful API usage are audited without key values or
  message content. Last-used time and request count cover successful API calls.

## Partner booking methods (SelfPay)

These are explicit clinic-only adapters, using SelfPay's established notification,
OTP, branding, read-only recipient portal and approval link. Only keys issued to
the configured SelfPay owner can have booking scopes. Other software should use
`/messages`; booking adapters for other products are not implemented in v1.
Prerequisites: enabled SelfPay integration, authorized owner, configured action
origins, working notification SMTP and unsealed key service. Existing provider
notification suppression remains honored.

Create `booking.json` with a real future Unix timestamp less than seven days away:

```json
{
  "external_id": "MSP-EXAMPLE-001",
  "subject": "Appointment request — Example Clinic",
  "body": "Private appointment details and requested slots for the clinic.",
  "participants": [
    {"email": "clinic@example.com", "name": "Example Clinic", "role": "provider"}
  ],
  "provider_action": {
    "url": "https://myselfpay.onesmarter.com/REPLACE_WITH_EXISTING_CLINIC_ACTION_PATH",
    "expires_at": 0
  }
}
```

Replace `expires_at: 0` (intentionally invalid) with your actual action expiry.
Use a genuine SelfPay-generated clinic action URL; the example path is not a route.
The URL origin must match `provider_action_origins`. SelfPay still verifies clinic
identity with its own OTP. This API grants no SelfPay session or approval bypass.

```bash
curl --fail-with-body "$SECUREMAIL_BASE_URL/bookings" \
  -H "Authorization: Bearer $SECUREMAIL_API_KEY" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: booking-MSP-EXAMPLE-001' \
  --data-binary @booking.json
```

HTTP 201 returns `id`, `url`, `external_id`, and provider-notification status.
Replays return 200. The returned URL is a portal navigation URL, **not** an
authentication credential; the actual email receives a recipient-bound invitation.
`delivery_mode` is optional but only `provider_only` is accepted. Exactly one
provider is required. No patient participant, patient notification or patient chat
is created. External references are isolated by key and cannot collide with the
legacy HMAC integration. Missing idempotency headers fail; changed replay payloads
return 409. Another API key cannot read or confirm this booking.

```bash
curl --fail-with-body "$SECUREMAIL_BASE_URL/bookings/BOOKING_UUID" \
  -H "Authorization: Bearer $SECUREMAIL_API_KEY"
```

Read returns `booking_status: "requested" | "approved"`, read-only flag, source,
navigation URL and timestamps. After SelfPay has actually approved the request:

```bash
curl --fail-with-body "$SECUREMAIL_BASE_URL/bookings/BOOKING_UUID/confirmation" \
  -H "Authorization: Bearer $SECUREMAIL_API_KEY" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: booking-MSP-EXAMPLE-001-approved-v1' \
  --data '{"event_id":"approval-v1","body":"Your clinic approved this appointment in SelfPay."}'
```

This records an encrypted provider-only confirmation and updates the portal's
approval status. It does not modify the SelfPay database, send patient mail or
send an additional clinic email. Repeated event IDs with changed content return
409; identical replays do not duplicate messages. Revoked bookings return 404.
Booking scopes do not grant access to legacy integration conversations, ordinary
messages or conversations owned by other keys.

## Test checklist

1. Confirm the enabled SelfPay owner, SMTP and allowed provider-action origins.
2. For /messages, send only to a clinic mailbox you control. Omit template_id and
   reply. Confirm Patient Care notification and OTP templates and reply=false.
3. For /bookings, use a synthetic booking and a genuine SelfPay-generated action
   URL with a future expiry. Never use a production patient's booking for testing.
4. Confirm only the clinic receives mail. The clinic verifies its mailbox in
   Secure Mail and sees a read-only request with the review action.
5. Follow the action to SelfPay. SelfPay's own OTP remains required.
6. Only after approval in SelfPay, call /confirmation and read the booking again;
   expect approved. This API does not approve anything in the SelfPay database.
7. Verify no patient notification/chat is created by the booking endpoints.
8. Revoke the test key. Existing HMAC integration credentials are unaffected.

The bearer caller is trusted to report a completed approval; do not expose the
confirmation credential to browsers. This is not a signed approval attestation
from SelfPay and does not independently verify its database state.
