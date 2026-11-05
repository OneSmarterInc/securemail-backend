## MySelfPay center-only booking notifications

The clinic booking notification is sent only by Secure Mail. Keep
`SECURE_MAIL_ENABLED=true` in the active SelfPay environment; restart the SelfPay
API and booking-chat worker after environment changes. A Secure Mail outage
leaves the handoff queued for retry, without a direct SelfPay booking email.
SelfPay's existing clinic OTP is still required after following the approval
link. Secure Mail email verification does not authenticate a SelfPay session.

Deploy the matching Secure Mail frontend read-only UI: it displays the original
request and the existing MySelfPay approval link, with no reply composer. The
backend also rejects replies, independently of the UI. Patient mobile login and
dashboard status remain in SelfPay. No patient email enrollment is restored.

This update adds no schema migration or encryption-key change. Preserve existing
environment files, databases, certificates, key store and unseal secret. Restart
only application APIs/workers for this update, not the key service. Test with a
new synthetic booking; do not replay historical patient queues.

Local validation (2026-11-05): 29 portal tests passed; backend lint and formatting
checks passed. The full synthetic suite returned 619 passed, 19 skipped and one
failure in the unrelated shared-mail OTP test's latest-job selection. All eight
tests in that module passed on a focused rerun. This is not an all-green full-suite
claim or live deployment evidence. The matching frontend build and two mocked
browser tests passed. SelfPay booking/clinic tests verify no direct booking email,
retry without SMTP fallback, OTP single use and clinic ownership checks.

A signed selfpay integration request may set `delivery_mode: "provider_only"` with exactly one participant whose role is `provider`. A valid allowlisted `provider_action` is required. This mode creates no requester mailbox, patient invitation or requester receipt. The verified provider can view the encrypted request and open the clinic action; replies are rejected with 403. Existing two-party contracts remain unchanged. Deploy this support before enabling center-only delivery in MySelfPay. Existing mTLS, HMAC/replay protection, suppression, encryption and idempotency checks still apply.

No patient mailbox, email or replies are added to MySelfPay. Configure the existing selfpay integration with suppress_provider_notifications=false and the exact MySelfPay origin in provider_action_origins. Its existing notification SMTP/outbox, key-service custody and mTLS/HMAC verification remain required. Deploy this backward-compatible Secure Mail backend change before enabling the MySelfPay center-only handoff. Existing two-party threads are preserved; MySelfPay does not replay their queues. No database migration is needed for this contract extension.
