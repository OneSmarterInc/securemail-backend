# SelfPay private booking messages

## Clinic invitation wording update — 2026-11-05

New SelfPay clinic invitations explain MySelfPay, name the requesting patient and
clinic, and show the unique reference labeled "MySelfPay booking reference".
The HTML button reads "Review appointment request" and leads to the existing
email-verified Secure Mail conversation. No requested dates/times, exam details,
patient email or residential address appear in this notification. The patient
name is the explicitly requested exception to the earlier generic-email policy.
It uses the existing support@onesmarter.com environment SMTP transport. Other
notifications and OTPs retain their existing wording. Already queued payloads
and already delivered invitations are not rewritten or automatically resent.
The wording-only release needed no migration. The subsequent approval-flow release below also updates both frontends.

Booking requests are created after verified submission, before clinic approval.
The initial request (including preferred appointment windows and the existing
SelfPay clinic action link) is visible only to the provider participant.
When the clinic marks the request scheduled, SelfPay durably queues one
`booking_confirmed` event. Secure Mail stores it as a requester-only message
with the existing patient booking/tracking link. Ordinary replies remain shared.

The server filters private messages, summaries, pagination and unread state by
participant role. Message audience is bound to the encryption context. Previously
created SelfPay initial messages are also hidden from requester reads. This
cannot retract content a recipient accessed before this change.

Except for the initial clinic invitation's name/clinic/reference fields above,
notifications contain no booking details or action tokens. Invitations, new-message
notices and portal OTPs use Secure Mail's environment SMTP credentials and
support@onesmarter.com. Recipients click the secure-message link, verify their
email with the normal OTP flow, then read the authorized message and links.
SelfPay's separate account/clinic authentication remains unchanged.

## Deploy in order

1. Back up databases. Deploy Secure Mail backend and apply migration
   `0026_portal_private_system_messages` using its configured production environment.
2. Deploy the Secure Mail frontend. It displays private system confirmations and
   their authorized, unexpired action links.
3. Deploy SelfPay backend and apply migration `0011_booking_chat_events` using
   its configured production environment. Do not execute standalone SQL manually.
4. Restart SelfPay API and its existing `process_booking_chats --watch` worker.
   Keep Secure Mail's outbox worker running and key service unsealed.
5. Set the SelfPay integration's `suppress_provider_notifications` to false and
   `provider_action_origins` to ["https://myselfpay.onesmarter.com"] (or the actual
   approved SelfPay origin). Keep existing HMAC/mTLS configuration.
6. Secure Mail environment: configure EMAIL_HOST, EMAIL_PORT, EMAIL_HOST_USER,
   EMAIL_HOST_PASSWORD, EMAIL_USE_TLS/EMAIL_USE_SSL for the provider authorized
   to send as support@onesmarter.com. Do not copy credentials into SelfPay for
   these messages. Restart Secure Mail API/outbox after environment changes.
7. Verify with synthetic bookings: both clinic and patient receive initial notices;
   patient alone sees the confirmation; replies are shared; each recipient must
   complete OTP. Check both portal views and retry a delivery without duplicates.

Confirmation events are encrypted in SelfPay's durable outbox and deduplicated
by request/event ID in Secure Mail. A failed delivery retries without undoing
clinic approval. Existing scheduled requests are not automatically backfilled.
Links retain their existing expiry; a message remains after its action expires.
A 'scheduled' status does not invent an exact appointment time.

Local validation is not evidence of a production deployment or live SMTP delivery.

## Approval-flow update — 2026-11-05

New threads queue an initial invitation to each participant. The patient receives
an encrypted, requester-only receipt containing clinic name and booking reference;
the provider retains the detailed private request and approval action. Neither
participant can read the other's private system message. Ordinary replies remain
shared. No appointment timing appears in the initial notification email.

Authenticated thread details expose `booking_status` (`requested` / `approved`).
Approval derives from the authenticated, idempotent SelfPay confirmation event,
not browser input. Both participants see the status; the confirmation body and
patient tracking link remain requester-only. Worker retries can delay the status
until the confirmation event reaches Secure Mail. Rejection/cancellation status
synchronization is outside this change.

SelfPay's patient receipt and authenticated clinic result show Open secure chat
using the existing backend link. Clinic details refresh every 15 seconds while
verified. Opening the clinic verification screen automatically requests one OTP;
resend remains visible and disabled for the server cooldown (60 seconds default).
Existing OTP verification, session expiry and rate limits remain enforced.

This release has no new schema migration or key rotation. Deploy Secure Mail
backend and both Vercel frontends. Existing SelfPay backend f1f59a7 already returns
the links and queues approval events. Existing thread invitations are not resent
and old threads are not backfilled with patient receipts. Test with a new synthetic
booking. Production delivery and live approval still require verification.

## Dedicated SelfPay sender

Deployments can now enable the separate SelfPay SMTP route documented in
[SELFPAY_SMTP.md](SELFPAY_SMTP.md). With that route enabled, SelfPay secure-portal
invitations, OTPs, replies and approval notices use its configured sender and
Reply-To instead of the general support sender described above.
