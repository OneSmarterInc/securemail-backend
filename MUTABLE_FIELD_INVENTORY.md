# Encrypted-field rollback inventory

Candidate — internal design decision 2026-11-04, independent review pending.

Inventory covers application write paths in `smtp_settings.py`, `accounts.py`,
`auth.py`, `conversations.py`, `direct_chats.py`, `portal.py`, storage and migration
helpers. “Insert-only” below describes semantic content, not ciphertext bytes
that maintenance or staging promotion can rewrite.

| Field / content | Semantic update behavior | Candidate guard |
| --- | --- | --- |
| StaffSMTP.password_ciphertext | Replaced when staff SMTP credentials change | `smtp-credential=<staff UUID>` current-DEK digest |
| StaffUser.mfa_secret | Enrollment/reset replaces or clears the seed | `mfa=<staff UUID>` current-DEK digest; existing MFA guard retained |
| Conversation subject | Written at creation; no current edit endpoint | Excluded; adding an editor requires revisiting this inventory |
| EvidenceCapture metadata / source metadata | New evidence or upload record; timestamp proof assigned once | Excluded; no current replacement-content editor |
| Message and PortalMessage bodies | New message records; no body edit endpoint | Excluded |
| PortalThread metadata | Placeholder initialized during creation transaction | Excluded; no subsequent edit flow |
| PortalMailbox encrypted email | Created for stable identity; deduplicated by identity hash | Excluded |
| DeliveryJob payload | Written once, cleared after lifecycle completion | Excluded |
| Attachment content | New uploads; staging promotion re-encrypts the same content | Excluded from mutable-content ledger; not literally immutable ciphertext |

Custody migration can freshly encrypt existing plaintext; service-native rewrap
preserves the DEK. Both are maintenance paths, not permission to edit content.

## State and migration

The candidate `current_deks(context,digest)` table lives in the key service,
outside the application DB. Wrap updates the current digest for the two scoped
contexts; unwrap rejects a missing or older digest. Existing MFA fingerprints
are imported during explicit copy migration. Existing SMTP ciphertext without
trusted ledger state requires credential re-entry; reading it never enrolls it
automatically. Do not expose its plaintext as a migration shortcut.

Every authenticated audit event commits the protected-state digest, including
this table. External signed checkpoints commit the state and audit prefix.
An application DB counter alone would not provide this protection.

The application DB and key service do not share a distributed transaction.
If key-service wrap commits but the application update fails, the previous
credential may become unusable; re-enter the credential through the authorized
flow. This deliberately favors refusal over accepting a stale secret.

## Residual risks / sponsor decision item 27

The candidate is disabled by default and cannot run in production. Until its
authenticated state and external checkpoints are deployed and independently
reviewed, key-store rollback remains a release blocker. Even with the candidate,
restoring an authentic, never-exported tail during an outage may evade freshness
detection after restart. An explicit custodian outage override also gives up
external freshness verification temporarily. These are separate risks from
application-only ciphertext rollback and require sponsor/reviewer acceptance.

Tests replace a StaffSMTP v2 ciphertext with its authentic v1 ciphertext and
require decryption failure. Further tests roll back the key-service ledger and
require the protected-state commitment check to fail.
