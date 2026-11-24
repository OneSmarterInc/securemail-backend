# OneSmarter Secure Mail public API v1

Use an API key from **Access > API keys** to call Secure Mail from your server.
This API sends encrypted, protected messages. It is not an ordinary SMTP relay.

## Choose a profile guide

- [Secure Mail / custom partner branding](PUBLIC_API_SECUREMAIL.md)
- [SelfPay / established Patient Care](PUBLIC_API_SELFPAY.md)

Profile controls notification/OTP branding and delivery configuration; scopes
control API access. Booking routes always use the SelfPay workflow. Template
routes are callable with either profile, but SelfPay message sends reject template_id.

## Create and protect a key

1. Sign in to the staff portal as an active, MFA-enrolled administrator with
   privilege-management permission.
2. Open Access > API keys. Select Create API key.
3. Choose a name, permissions, notification profile and expiry (1–365 days; default 90).
   Use Secure Mail for normal/custom-branded software. SelfPay profile is restricted
   to the configured SelfPay owner and retains Patient Care notification/OTP templates.
4. Confirm a fresh MFA code if requested. Copy the secret shown once and save it
   in your server's secret manager or environment. The database stores only its
   SHA-256 digest. Keys contain 32 random secret bytes; they are not passwords.
5. Never put keys in browser/Vite code, URLs, source control, screenshots or logs.

Production base URL: `https://securemailbackend.onesmarter.com/api/v1`
Local base URL: `http://localhost:5173/api/v1` (synthetic development only).

All requests require `Authorization: Bearer YOUR_API_KEY`. HTTPS is required
outside synthetic development. Cookies, staff sessions and query-string keys
cannot authenticate these endpoints. A key cannot log into admin or custody APIs.

## Permissions and endpoints

| Method | Path | Required permission | Purpose |
|---|---|---|---|
| GET | `/status` | `status:read` | Key-service readiness and API version |
| POST | `/messages` | `messages:write` | Send to the protected stream for this key, sender and recipient |
| GET | `/messages` | `messages:read` | List only conversations created with this exact key |
| GET | `/messages/{id}` | `messages:read` | Read that key's conversation, messages and delivery status |
| POST | `/templates/preview` | `messages:write` | Validate markup and return a preview as JSON; no email sent |
| POST | `/templates` | `messages:write` | Store an encrypted notification template; idempotency key required |
| GET | `/templates` | `messages:read` | Paginated list of this key's templates |
| GET | `/templates/{id}` | `messages:read` | Read this key's template |
| POST | `/bookings` | `bookings:write` | Create a clinic-only SelfPay conversation |
| GET | `/bookings/{id}` | `bookings:read` | Read this key's booking status |
| POST | `/bookings/{id}/confirmation` | `bookings:write` | Record an approval already completed in SelfPay |

These are the complete key-authenticated endpoints in v1. Attachments, ordinary
email/Nophi, message replies, account management, audit
exports and key-service operations are not available through these keys.

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

## Local operation and release limits

Local preview uses existing admin accounts and stores. It is synthetic-only;
production cryptographic review, custody and transport gates remain unchanged.
Local tests do not establish production readiness or SMTP delivery. API keys are
bearer credentials: anyone who obtains one can exercise its granted permissions.
Use a separate key per integration and the smallest set of permissions.

## Admin screen: generate and filter keys

Open Access > API keys (`/#/access/api-keys`). Search by name, filter by active,
expired or revoked status, and filter by permission. Filters combine and apply
before pagination. Clear filters restores the full organization-scoped list.
Status describes expiry/revocation; owner eligibility is also checked on every
API call. Creating and revoking require privilege-management permission and
recent MFA. The secret is shown only once.

## Customize notification HTML and CSS

This customizes the email invitation, not the encrypted message itself. Do not
put confidential patient or document details in template HTML or its plain-text
alternative: those fields are sent through ordinary SMTP. The `subject` and
`body` of POST /messages remain protected portal content. Secure Mail appends its
own verification button and service attribution; the sender cannot substitute
that destination. SMTP identity and recipient authentication remain unchanged.

Example template.json:

```json
{
  "name": "Clinic notification",
  "html": "<h1 style=\"color:#087e83\">A secure update is available</h1><p>Please use the button below to verify your email and read your message.</p>",
  "css": "font-family:Arial;background-color:#ffffff;padding:24px",
  "text": "A secure update is available. Verify your email using the link below."
}
```

Preview without sending or saving:

```bash
curl --fail-with-body "$SECUREMAIL_BASE_URL/templates/preview" \
  -H "Authorization: Bearer $SECUREMAIL_API_KEY" \
  -H 'Content-Type: application/json' \
  --data-binary @template.json
```

The JSON response contains `html`, `text`, and `preview_only: true`. The preview
button uses example.invalid and cannot access a real conversation. If embedding
preview HTML in your own UI, use a sandboxed iframe without script permissions.

Save a reusable template:

```bash
curl --fail-with-body "$SECUREMAIL_BASE_URL/templates" \
  -H "Authorization: Bearer $SECUREMAIL_API_KEY" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: clinic-template-v1' \
  --data-binary @template.json
```

HTTP 201 returns `{"id":"template-uuid"}`. Add that UUID as `template_id` to the
existing POST /messages JSON. Repeating template creation with the same
idempotency key and payload returns HTTP 200 and the original ID. Changed data
with that idempotency key returns 409. Templates are immutable: create a new one
for a new design. Maximum 100 per API key. Other keys cannot list, read or use
these templates. Template contents are encrypted at rest and copied into the
encrypted delivery job so queued emails have a stable design.

Required fields: name (80 characters), html (20,000), text (10,000). Optional css
(2,000). `css` is a list of declarations for the outer content wrapper, not a
stylesheet; inline `style` attributes use the same rules. No interpolation or
server-side template language is executed.

Allowed HTML: p, div, span, h1–h3, strong, em, b, i, br, hr, ul, ol, li, table,
tbody, tr, td, th. Tags must be balanced, at most 20 levels deep. Only the style
attribute is accepted. Scripts, images/tracking pixels, links, forms, iframes,
stylesheets, comments and other attributes are rejected with HTTP 400.

Supported CSS:

- color, background-color, border-color: #RGB or #RRGGBB.
- font-size, padding (and top/bottom/left/right), margin (and top/bottom),
  border-radius, border-width: 0px–99px, one value per declaration.
- text-align: left, center, right.
- font-weight: normal, bold, 400, 500, 600, 700.
- font-family: Arial, Verdana, Georgia, sans-serif, serif.
- border-style: solid, none; border-collapse: collapse, separate.

URL loading, positioning, animation, expressions and arbitrary CSS are rejected.
Email clients may render supported styling differently. This is intentionally a
restricted email-markup API, not an unrestricted webpage or SMTP relay.

Example message using the returned template ID:

```json
{
  "sender": "authorized-staff@onesmarter.com",
  "to": "recipient@example.com",
  "subject": "Protected information",
  "body": "Confidential content stays in the secure portal.",
  "template_id": "REPLACE_WITH_RETURNED_TEMPLATE_UUID"
}
```

POST this JSON to `/api/v1/messages` with your Bearer header and a new
`Idempotency-Key`. The server loads only a template owned by that API key,
validates its markup again when rendering, and inserts the actual recipient
verification link. The plain-text part always includes the same secure link.

## Complete branded recipient flow

`reply` is an optional **JSON boolean** on POST `/messages`, default `false`.
With `true`, verified recipients may reply and upload through the normal secure
portal. With `false`, the portal shows the message and conversation status but
hides the composer, New message, reply and upload controls. The server also
rejects recipient replies/uploads with HTTP 403 `replies_disabled`; hiding the
buttons is not the security boundary. Existing attachments remain readable when
authorized. Staff access is unchanged. This is a per-message conversation policy,
not a global key setting; API list/detail responses include `reply`. Each new
message request sets the stream's current policy: omitting the flag disables
replies again, even if an earlier message enabled them. Include `"reply": true`
on every send intended to keep replies enabled. Strings such as `"false"`, numbers
and null are invalid. There is no separate public reply-all enable flag; API
streams contain one recipient and cannot use reply-all to reach other senders.
SelfPay `/bookings` conversations are always read-only, independent of this option.

1. Your server creates a template with notification HTML/text, optional OTP
   HTML/text, and an optional portal theme. Preview it before saving.
2. POST `/messages` with `template_id`. Only a notification goes through email;
   the message's subject and body stay encrypted in Secure Mail.
3. The recipient clicks the recipient-bound invitation. The portal displays the
   partner identity and masked, noneditable destination. For API invitations it
   automatically requests a code for that designated mailbox. GET/link scanners
   do not send codes; the portal makes a rate-limited POST after loading.
4. The OTP email uses the template's OTP design if supplied, otherwise the normal
   Secure Mail template. The code is generated by Secure Mail, never by the API caller.
5. A correct, unexpired, unused code opens that recipient's conversation. Colors
   and logo remain on the recipient page after verification and session reload.
   Invalid codes, other invitation codes, expired sessions and revoked access
   remain blocked. Branding does not change authorization.

No recipient account, API key or staff password is needed. The software's API key
must never be sent to recipients. The API cannot retrieve OTPs or bypass verification.
Code lifetime is 10 minutes; resend cooldown is 30 seconds. Existing rate limits,
attempt limits and 15-minute recipient idle-session controls remain enforced.

### Notification + OTP + portal theme example

Save this as `template.json` and use the preview/save commands above:

```json
{
  "name": "XYZ recipient experience v1",
  "html": "<h1>A secure message is waiting</h1><p>XYZ Software has sent you a protected message. Continue below to verify your email.</p>",
  "css": "font-family:Arial;background-color:#ffffff;padding:24px",
  "text": "XYZ Software has sent you a secure message. Continue to Secure Mail to verify your email.",
  "otp_html": "<h1>Verify your email</h1><p>Use the code below to open your XYZ Software message.</p>",
  "otp_css": "font-family:Arial;color:#123456;padding:24px",
  "otp_text": "Use the code below to open your XYZ Software message.",
  "theme": {
    "name": "XYZ Software",
    "primary": "#123456",
    "background": "#f8f8f8"
  }
}
```

`otp_html` and `otp_text` must be supplied together; `otp_css` follows the same
restricted CSS rules as notification CSS. Limits: OTP HTML 20,000 characters,
OTP text 10,000, OTP CSS 2,000. Secure Mail appends the real code, expiry and
security instructions outside partner HTML. No placeholders are executed.
Preview returns `otp_html` with dummy code `000000`, `otp_text`, and `theme`, in
addition to the notification preview. It does not queue mail or create a challenge.

The partner name and accent color apply to both custom email designs. The portal
theme supports `name` (1–80 characters), `primary`, `background`, and optional
`logo_png` containing **raw base64 PNG bytes**, not a URL or data-URL prefix.
Logo limit: 64 KiB decoded, 512 × 512 pixels. SVG, external images and tracking
URLs are not accepted. The logo is displayed beside the partner name on the
recipient page, not embedded in the emails. Hex colors require six digits;
primary must support white text at 4.5:1 contrast, background must support the
portal's dark text at 4.5:1. White form/content surfaces and security notices are
application-controlled. Arbitrary page CSS/layout or custom login forms are not supported.

The presentation is encrypted and snapshotted into queued notification/OTP jobs.
Only the safe theme is returned before OTP; template HTML, private subject/body
and keys are not. Template access is isolated by API key. A new template version
affects only messages that explicitly select it. Existing messages retain their
design until a new message in the same stream explicitly selects a new template.
Omitting template_id on subsequent messages preserves the stream's design;
queued emails retain their original snapshots. New streams without a template
retain standard Secure Mail branding.

### Shared conversation stream and recipient Archive

Repeated POST `/messages` calls with the same API key, normalized sender and
recipient append to one active protected conversation. Every new idempotency key
creates a new encrypted message and queues a notification, returning HTTP 201
with that same conversation `id`. Repeating an idempotency key returns 200 without
duplicating either. The latest subject becomes the conversation title. Revoked
conversations/grants are never revived; a subsequent send starts a new stream.

Different API keys remain separate streams, even if they use the same sender
address, so one integration cannot read another integration's content. Existing
historical duplicate conversations are not merged or deleted automatically.

After email OTP verification, **Message archive** lists active API conversations
addressed to that exact verified email, including other senders and organizations.
The recipient can search by sender and open another conversation without entering
another OTP during the same valid session. Each conversation retains its own
theme and reply policy. Switching preserves the original absolute and idle
deadlines; expired, revoked and other-email grants are inaccessible. A URL alone
cannot authenticate a mailbox or reveal its Archive.

These are recipient-session endpoints, not API-key permissions:

- GET `/recipient-api/recipient/inbox?q=sender&page=1&page_size=25`
- POST `/recipient-api/recipient/inbox/{conversation_id}/open` (requires CSRF)

The server derives the mailbox from the verified session; callers cannot select
an email in query/body fields. Legacy staff invitations and the SelfPay clinic
integration inbox are not added to this API-recipient Archive. API-key reads still
return only the calling key's streams, regardless of what the recipient can view.

### SelfPay stays separate

Create a separate key with **SelfPay notification profile** for new SelfPay
message triggers. Internally this is `notification_profile: "selfpay"` on key
creation; the default is `securemail`. Only the configured, enabled SelfPay owner
can create or send through this profile. Notification and OTP emails use existing
SelfPay templates, Patient Care identity, and SelfPay SMTP settings. Custom
`template_id` is rejected for this profile. The standard Secure Mail profile is
used for other software. Neither profile allows arbitrary SMTP credentials/senders.

Creating a key does not enable, replace or replay any existing SelfPay trigger.
The existing HMAC integration remains unchanged. Choose the new methods explicitly
at the caller; do not call old and new methods for the same intended notification.

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
