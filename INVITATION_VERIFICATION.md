# Recipient-bound invitation verification

New partner notification links use a signed mailbox/thread reference in the URL
fragment. They contain no plaintext email. The link permits identifying the
recipient and requesting a code, never reading messages or authenticating.
Existing links without this reference retain manual verification.

Opening a new link performs a CSRF-protected POST after session bootstrap. The
server resolves the email from the active membership and encrypted mailbox,
ignoring caller-supplied email/source. The UI displays this address read-only.
A browser-bound challenge is reused on automatic refresh; explicit resend obeys
the existing cooldown and rate limits. A forwarded link still sends the code only
to its intended mailbox. JavaScript-capable email scanners can trigger a code;
GET requests cannot, and existing quotas bound dispatch.

Starting verification revokes the old mailbox session. While an invitation is
pending, manual email switching is rejected. Verification rechecks recipient and
thread revocation. Every inbox read/reply independently checks active membership;
a thread ID is never authority. MySelfPay approval still requires its own OTP.

The signed reference remains usable while membership, owner and integration are
active (matching persistent invitation links). Keep Django's signing secret and
any configured fallback secrets protected. A person possessing the full link can
see its recipient email through bootstrap, but cannot read the inbox without OTP.
The fragment is removed after verification. Tokens must not be logged or added
to analytics. No patient recipients are added by this change.

Deploy backend before frontend. No schema, dependency, environment, custody or
cryptographic envelope changes are required. Do not restart the key service or
reinitialize stores. Existing sent/queued links are not rewritten or resent.

Validation: 38 portal tests; seven Playwright checks (360px/1440px, automatic
single request, read-only email, cooldown, verification and legacy links);
frontend production build. Full backend regression: 634 passed, 19 skipped; ruff check and format passed.
All checks use synthetic data. Live delivery and production are not verified here.

