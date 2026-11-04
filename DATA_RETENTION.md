# Submitted documents, access expiry and retention

Updated: 2026-10-28. Product behavior clarification; not an infinite-durability or legal-compliance guarantee. This document expands PRD D08 and FR-23.

## Document-storage decision - 28 October 2026

Uploaded documents will be stored on persistent disk attached to the AWS instance running the application. This supersedes private S3 as the primary attachment-storage baseline. Engineering assumption: use a dedicated persistent EBS data volume, mounted outside the application/container filesystem, with deletion on instance termination disabled and mount availability checked before accepting writes. Files remain application-encrypted and are served only through authorized application endpoints, never as public static files.

This selects storage placement, not an AWS geographic region. Region, volume sizing, backup destination/schedule/retention and recovery targets remain undecided. A backup on the same instance is not sufficient protection against loss of that instance. Retained conversation records, files and usable keys must be recoverable together. Keep the key-service custody boundary and separately held recovery secret; this decision does not authorize placing recovery secrets beside uploaded files.

AWS-managed EBS volume encryption uses AWS KMS, including its default managed key. Do not silently enable it while claiming zero KMS dependency. Application encryption remains required; the OS/volume encryption approach must be reviewed against the no-KMS requirement before deployment. See [AWS EBS encryption](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html). No AWS resources or encryption settings were changed by this documentation update.

The existing S3 adapter is optional, not the selected primary attachment backend. Immutable audit archival and off-instance backups are separate decisions; this change does not claim local disk provides Object Lock or host-admin-proof immutability.


## Product contract

Successfully submitted visitor files and messages remain associated with their original conversation. There is no automatic age-based deletion of committed submissions in the product baseline. Visitor logout, session timeout, access-link expiry, revocation or staff account deactivation must not delete these records or their required keys.

Authorized assigned staff can continue reading retained records after recipient access ends, provided the data, key hierarchy and infrastructure remain available. Account-management privileges alone do not grant content access. Keeping files on the portal means persistent encrypted storage linked to the conversation, not a copy in a visitor browser session.

| Event | Recipient behavior | Stored submission / staff behavior |
| --- | --- | --- |
| Session timeout or logout | Must verify again; only possible while the grant/conversation remains eligible | Committed messages/files remain on the same thread; assigned staff retain read access |
| Invitation/conversation access expiry | No subsequent recipient access through the expired grant | Existing submissions retained; staff can read, but current implementation also blocks new staff replies on expired conversations |
| Grant/conversation revocation | Recipient access stops, including already verified sessions on subsequent requests | Records retained; assigned staff can still read |
| Browser closed | Session rules determine whether reverification is needed | No deletion of a committed submission |
| Upload staged but reply not submitted | Not yet a completed conversation submission | Subject to a separately defined abandoned-upload lifecycle |
| Rewrapping or root rotation | No intentional change to access permissions | Preserve readability and original conversation linkage |

Reverification opens the same authorized conversation; it does not create a new thread. It cannot revive an expired or revoked grant. A future renew/reinvite workflow would need explicit implementation and authorization; none is promised by this document.

## Current code evidence

- `conversations.recipient()` checks the session expiry; `active_grant()` checks recipient/conversation revocation and access expiry. These guards do not delete content.
- `owned()`, `conversation_detail()` and the staff branch of `download()` authorize retained access by organization and owner, independently of recipient expiry/revocation.
- Attachments committed to messages are linked through `Attachment.message` and `Message.conversation`; there is no attachment session-expiry field or committed-document purge job in the inspected code.
- `attach_files()` writes a final object and removes the superseded staged object after commit. This is upload finalization, not deletion of the submitted document.
- The existing retained-file regression covers staff reading after recipient revocation. Separate session/access-expiry and cleanup-race cases remain required; historical tests do not prove all retention cases or infinite availability.

## Boundaries and policies still required before real data

Indefinite retention means **no scheduled expiry of accepted content**, not a promise that storage can never fail or a rule that every byte must be retained forever.

- Approve exceptional deletion/legal-hold procedures, actors, reasons, recordkeeping and backup treatment. No generic portal Delete action is implied.
- Decide retention separately for audit archives, generated exports, authentication/OTP delivery copies, abandoned uploads, malware/quarantine artifacts, old object versions and backups. These must not inherit indefinite document retention automatically.
- Define region/data residency, storage growth/capacity, billing ownership, alert thresholds and recovery targets. Do not enable bucket lifecycle rules that expire live submitted objects or required versions.
- Keep required decrypt-only keys, encrypted private material, formats and recovery authority for the entire retained-content and backup horizon. Session expiry must never trigger key destruction.
- Backup and restoration must cover the database-to-object references and key store together. A surviving object without usable keys is not a recoverable document.

## Required verification

Submit a visitor file, record its conversation/message/object identifiers, expire only the recipient session, then prove recipient denial and exact-byte staff download on the same thread. Repeat separately for logout, access expiry and revocation. Reverify while the grant is valid and prove the same thread is opened. Verify rejected expired/revoked access does not mutate storage. Test abandoned-upload cleanup concurrently with finalization so committed files cannot be collected as orphans. Repeat retained reads after service restart, wrapping/root rotation and isolated restoration.

UI copy: **“Access expires on …”**, not **“Files disappear on …”**. Submission success should distinguish **“Submitted to this conversation”** from a staged upload. Never display **“Stored forever”** as a durability guarantee.
# Partner inbox records

Partner conversation messages and encrypted mailbox/thread metadata follow the existing retained-conversation policy. They are not deleted when an external application's booking expires. Align cross-service deletion/retention requirements before production enablement; this integration does not introduce automatic deletion of committed chat content.

OTP validity is ten minutes, five attempts and one use. Mailbox sessions have 15-minute idle and eight-hour absolute limits. Used/expired challenges and sessions remain non-authorizing records; operational cleanup must follow the same reviewed database process as other authentication records. Signed service-request nonces are deleted after their replay-protection horizon. Notifications contain no patient name, phone, exam, appointment windows or reply body. Delivery payloads and OTPs reuse the existing encrypted outbox and its lifecycle.
