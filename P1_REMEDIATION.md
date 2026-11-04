# P1 review remediation — 29 October 2026

This records code changes and their limits, not production approval. The production
startup block remains unchanged. Retain original keys, objects, databases and
backups; no existing encrypted records were rewritten or deleted in this work.

| Finding | Implemented change | Remaining evidence or limitation |
| --- | --- | --- |
| P1-1 | Wrappers require auth_v=1 and HMAC-SHA256 over the canonical wrapper plus trusted context. A domain-separated HKDF key is derived from private key material inside the service (or synthetic local protector). Verification precedes decapsulation/DEK release. Public-key forgery tests cover attachment and MFA contexts; independent implementation vectors include the MAC. | MACs do not prevent replay of an old valid envelope or rollback of an entire trusted store. An independently protected version/commit ledger and coordinated recovery design remain required. The revised candidate needs external review. |
| P1-2 | Rotation, import and root rotation fsync an encrypted-key snapshot before live commit. Snapshot failure rolls back activation. Restore CLI validates integrity, custody, audit chain and every private record, publishes a new sealed store and refuses overwrite. | Local restore drill passes; actual off-host mount durability, failure domain, checkpoint freshness and disaster recovery remain pending. Extra pre-commit snapshots may exist after a failed live commit. |
| P1-3 | Normal init accepts an off-host-generated secret interactively without writing it locally. Local secret generation is explicitly synthetic-only. Serve requires an explicit backup directory. | Software cannot prove a person has removed all copies or has independent custody. Existing demo secrets were not moved/deleted. M-of-N/HSM selection, custody approval and operator drills remain release gates. |
| P1-4 | User chose retention of original ownership. Existing deactivate/reactivate UI and session-version invalidation are preserved; inactive owners block recipient access/submissions and queued owner-related delivery. Reactivation requires fresh staff sign-in. | No reassignment or automatic admin content access. Notifications cancelled during inactivity require an explicit reviewed retry/new notification. |
| P1-5 | Recipient idle time extends only on authenticated user activity; polling does not extend it. Expired sessions route to re-verification. Draft text/upload references stay in memory through re-verification; explicit lock or unavailable grant clears them. Poll requests are cancelled on stage change. | Drafts do not survive reload/tab close and remain subject to staged-upload cleanup. No browser persistent secret/draft storage was added. |
| P1-6 | Send disabled until preview matches the current payload. Ordinary submission carries the expected route; server recomputes under the organization lock and rejects mismatch before persistence. | Old ordinary-compose clients must adopt the updated contract. |
| P1-7 | Explicit permission-gated Nophi toggle and acknowledgement. Subject text alone does not downgrade. Clear normal-email routing label. | Pure historical policy matcher remains for reference; application boundary supplies only explicit consent. |
| P1-8 | Per-file upload percentage, Checking/Available/Not accepted states, live status region, cancellation and readable stored-state labels. | Checking means awaiting server acceptance; it is not an invented percentage for antivirus scanning. Network failures are not falsely labeled malware. |
| P1-9 | Settings API supplies supported cipher, storage configuration, scanner mode and current key-service readiness; UI labels consume those values. | Configuration presence is not a live storage durability/backup check or independent crypto certification. |

## Authenticated-format rollout and existing records

The hybrid suite and key-record AAD stay unchanged; the envelope profile adds
mandatory `auth_v=1` and `auth`. Missing/unknown authentication profiles fail closed.
There is deliberately no online switch to accept old unauthenticated v2 envelopes
and no command that blindly signs historical data. The old synthetic symmetric
v1 compatibility path remains subject to its existing local-only restrictions.

Before restarting an existing installation on this format, freeze writes, preserve
snapshots and inventory old envelopes without disclosing plaintext. Re-import
attachments from an independently trusted source and scan again; re-enroll MFA
seeds through verified recovery; reconcile messages against approved provenance.
Any legacy conversion tool needs explicit scope, transaction/failure handling and
reviewed source authenticity. Re-signing arbitrary old ciphertext would preserve
the forgery vulnerability. Existing records may become unreadable under the new
code until that migration/re-enrollment is completed. Do not delete them to bypass
this condition. Application/key-service versions must be deployed together.

The local running API/worker/key service have not been restarted onto this
incompatible format during remediation. Frontend source changes are visible through
Vite, but full mixed-version runtime behavior is not deployment evidence.

## Custody and rollback closure

Fund independent review of the exact MAC profile and authorized-write boundary.
Design a separately protected, monotonic per-resource version/commit ledger with
atomic application publication and recovery semantics before claiming rollback
resistance. Checkpointing only the same attacker-writable database is insufficient.
For custody, select a reviewed M-of-N or HSM-backed solution, independent custodians,
share/device replacement and compromise procedures. No home-written threshold
cryptography or claim of enforced off-host custody is introduced here.
