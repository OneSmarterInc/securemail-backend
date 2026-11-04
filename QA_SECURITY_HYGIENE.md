# Security hygiene remediation — 31 October 2026

## Implemented controls

- OTP, rate-limit and idempotency verifiers now use distinct Django salted-HMAC domains. New recovery codes contain 128 random bits and are stored with Argon2, independently of Django's signing key.
- Bootstrap requests are rate-limited before token validation. Recipient logout flushes the session and deletes its scoped cookie. An explicit invitation token takes precedence over a previous recipient session.
- Reactivation invalidates the previous password, MFA seed and recovery codes and issues a fresh password-recovery invitation. Conversation ownership is preserved.
- Evidence and SMTP connections reject NAT64, Teredo, 6to4 and private IPv4-mapped destinations before connecting. Deployment must also deny metadata/private-network egress, including any custom NAT64 prefix; EC2 metadata configuration is an infrastructure responsibility.
- Attachment and capture database digests are organisation-scoped HMAC-SHA256 tags over SHA256(file), using an independent DOCUMENT_INTEGRITY_KEY. Raw file SHA-256 remains in the encrypted manifest. Ciphertext bundle hashes remain public integrity checks. Equality within one organisation remains observable.
- Removed the retired browser prototype and sender-profile helpers. Migration 0021 wipes and drops retired organisation OTP credential fields.
- Default allowed hosts exclude testserver outside tests. Uploads retain the existing single bounded in-memory handler setting. ClamAV sockets use mode 660 and a shared scanner group.

## Upgrade and rotation

1. Back up the database and preserve existing deployment secrets securely before migration. Pause writes and deploy application code and migration together.
2. Set DOCUMENT_INTEGRITY_KEY to a securely generated independent random secret (at least 32 characters; init_local.py and init_compose.py generate 48 random bytes). Back it up separately from the database. Do not change it during DJANGO_SECRET_KEY rotation. Compose requires this setting.
3. Run `python manage.py migrate`. Migration 0021 is intentionally irreversible: it converts digest lookup values without decrypting or rewriting document bytes, wraps legacy recovery verifiers in Argon2, and deletes retired OTP credentials. Existing backups may still contain retired data; apply the approved backup-retention policy.
4. Restart application and worker processes together so they load the integrity key and new schema. Verify a retained document download and new upload.

Legacy recovery codes cannot be converted to Argon2(code) without knowing the code. Their old HMAC is instead Argon2-protected. Before rotating DJANGO_SECRET_KEY, retain the previous key in RECOVERY_LEGACY_KEYS until affected users replace their recovery codes through MFA re-enrolment. New codes do not need this compatibility key. A lost legacy key means those legacy codes cannot work; use administrator recovery instead.

DJANGO_SECRET_KEY_FALLBACKS permits temporary validation of old session signatures and OTP/idempotency verifiers. Remove old keys after their corresponding validity and replay windows. Rate-limit identifiers change on rotation and their old buckets are not reused. Never rotate during an attack without replacement edge limits.

Rotating DOCUMENT_INTEGRITY_KEY needs a planned re-tagging migration from encrypted manifests (and verification of staged attachments), not simply replacing the environment value. Changing it alone makes existing integrity checks fail closed.

## Build and deployment evidence

Runtime images are pinned by digest. Renovate configuration proposes reviewed updates; repository administrators must enable the Renovate integration. Existing pip-audit and full npm audit gates are retained. CI adds Bandit (including rejection of incomplete scans), redacted Gitleaks history scanning and Trivy high/critical gates for built application images. Pinning alone does not establish that an image has no vulnerabilities.

Run `python scripts/init_compose.py` with Docker running to resolve CLAMAV_GID from the pinned scanner image. Application containers join that group; the socket is not world-writable.

Local verification: 137 focused tests passed, Ruff clean, no model drift; Bandit reported no high-severity findings or scan errors. Docker image builds, Trivy, Gitleaks and live socket permissions require CI/Linux verification and are not claimed as locally executed.
