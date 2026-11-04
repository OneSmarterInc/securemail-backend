# SelfPay private booking messages

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

Notifications contain no booking details or action tokens. Invitations, new-message
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
7. Verify with synthetic bookings: clinic alone receives the initial notice;
   patient alone sees the confirmation; replies are shared; each recipient must
   complete OTP. Check both portal views and retry a delivery without duplicates.

Confirmation events are encrypted in SelfPay's durable outbox and deduplicated
by request/event ID in Secure Mail. A failed delivery retries without undoing
clinic approval. Existing scheduled requests are not automatically backfilled.
Links retain their existing expiry; a message remains after its action expires.
A 'scheduled' status does not invent an exact appointment time.

Local validation is not evidence of a production deployment or live SMTP delivery.
