# OneSmarter-owned encryption and key management

Updated 2026-10-28. The user excludes both OSIVault and AWS KMS from the production design. Our own isolated key service is the target; see [KEY_SERVICE_ARCHITECTURE.md](KEY_SERVICE_ARCHITECTURE.md). The separate service candidate is now implemented. Production approval remains outstanding.

## Ownership and implementation status

The application owns envelope formats, context binding, key-version records, rotation, migration, authorization integration and audit events. Cryptographic algorithms come from the pinned `cryptography==50.0.2` package and its OpenSSL backend. We do not implement AES, lattice arithmetic, elliptic-curve arithmetic or random generators ourselves.

Implemented candidate modules (all synthetic-only until review):

- `backend/apps/core/crypto.py`: data encryption/decryption, hybrid data-key wrapping, strict supported-suite checks and rewrapping.
- `backend/keyservice/protocol.py`: shared OSM-v2 implementation for both the local synthetic adapter and isolated service. ML-KEM-768 encapsulation and ephemeral X25519 agreement feed context-bound HKDF-SHA256; AES-256-GCM wraps the fresh document DEK. Authenticated v2 envelopes require `auth_v=1` and the wrapper MAC. Earlier unauthenticated v2 records are rejected; migration skips and reports them rather than silently adding authentication. Recover their content only from independently trusted original sources.
- `backend/apps/core/keyring.py`: tenant-scoped version creation, root-key protection, private/public consistency checks and active/decrypt-only lifecycle.
- `backend/apps/core/key_migration.py`: bounded, resumable migration of stored envelopes.
- `backend/apps/core/models.py`: `WrappingKeyVersion`, with a database constraint permitting only one active version per organization.
- `backend/tests/test_crypto.py`: real ML-KEM operations, rotation, tampering, tenant isolation, recovery, migration and rejection of removed protectors. Separate service tests exercise actual local HTTPS, restart, rotation and encrypted-backup recovery.

This is a working candidate application protocol. Passing tests and use of standardized algorithms do not make the protocol independently audited or FIPS validated. Production startup remains blocked pending [RELEASE_GATES.md](RELEASE_GATES.md).

The application and service reject duplicate JSON fields, non-finite JSON numbers and non-object envelopes before selecting an algorithm. Envelope versions must be integers, not booleans or floating-point aliases. Tests verify fresh DEKs, encapsulation material and nonces for repeated document encryption. Sealing the configured key service makes application reads, writes and rewrap fail closed; unsealing restores the same retained ciphertext without any local-key fallback. This proves application/service behavior, not post-quantum TLS negotiation.

## Sara's document in the current candidate

1. The API verifies Sara's conversation session, validates the file and requires an accepted scan result.
2. The service generates a new random 256-bit data encryption key (DEK) and 96-bit nonce. AES-256-GCM encrypts the bytes and authenticates trusted organization/resource context.
3. It selects the organization's active wrapping-key version. That version contains an ML-KEM-768 key pair and an X25519 key pair; private material is encrypted at rest.
4. Real ML-KEM encapsulation produces a shared secret and encapsulation ciphertext. A fresh ephemeral X25519 key produces a second shared secret. HKDF-SHA-256 combines the two fixed-length secrets with domain separation and bound metadata into a temporary 256-bit key-encryption key (KEK).
5. AES-256-GCM uses that KEK to encrypt the DEK with a separate random nonce and authenticated wrapper metadata. The temporary KEK and DEK are not saved in plaintext.
6. The encrypted file and envelope are stored privately. Synthetic development uses `.runtime/objects/`; S3 uses SSE-S3 (`AES256`) in addition to application encryption. Names, subjects, bodies, MFA seeds and notification payloads are also encrypted.
7. When authorized staff read it, the server recovers the indicated private-key version, decapsulates both parts, derives the same KEK, unwraps the DEK and verifies/decrypts the file. A changed context, ciphertext, suite, key identifier or authentication tag fails closed.

The service can read plaintext while processing authorized requests. This is server-side envelope encryption, not zero-access or browser-to-browser end-to-end encryption. Python does not guarantee immediate zeroization of immutable bytes; no such guarantee is claimed.

## Current key locations and required target changes

| Material | Created by | Persistent location | Access |
| --- | --- | --- | --- |
| Per-value/file DEK | Cryptography secure random generator | Only its encrypted wrapper inside the envelope | Recovered temporarily by the authorized application service |
| Temporary per-envelope KEK | HKDF from ML-KEM and X25519 shared secrets | Not persisted | Re-derived by the application service |
| Wrapping-version public keys | Cryptography ML-KEM/X25519 generation | Database, scoped to organization | Application metadata; validated against protected private material before encryption |
| Wrapping-version private seeds | Cryptography ML-KEM/X25519 generation | Currently database ciphertext under the local/legacy protector; target encrypted key-service store | Currently application memory; target key-service memory only, never portal staff/admins |
| Development root key | `scripts/init_local.py` | Ignored `.runtime/wrapping.key` | Local synthetic application process; not acceptable production custody |
| Self-managed root protector | Random 32-byte root encrypted by separate random recovery secret | Encrypted SQLite store; root in service memory after operator unlock | Dedicated custodian identity; no root/private export endpoint |

The legacy AWS adapter pins key ARNs, uses an allowlist and binds encryption context; it protects 96 bytes of private seed material. It has only mocked test evidence and is not approved for the new production target. Inventory and safely migrate any dependent records before removing it. The target service binds organization, version, suite and purpose, authenticates workloads, and exposes wrap/unwrap/rewrap operations rather than persistent private keys. No confidential names or document content enter visible context/audit metadata.

## AES-GCM and hybrid requirements

- Use fresh random 256-bit DEKs for new values/document versions and 96-bit nonces with a defined per-key uniqueness policy; never reuse a key/nonce pair for a new encryption call. Use a full 128-bit tag and verify it before releasing plaintext.
- A storage retry may resend an already completed envelope. Re-running encryption requires fresh DEK/nonce inputs. Rewrapping preserves the existing content key/nonce/ciphertext but generates a fresh wrapper.
- AAD binds stable trusted organization/resource/purpose identifiers. Canonical encoding is part of the protocol. Nonces/tags/public values are not secret; AAD does not encrypt metadata or replace authorization.
- ML-KEM is a KEM; X25519 establishes a traditional shared value. The temporary KEK is derived, not persisted. A wrapping-key version means persistent private/public material, not the temporary KEK.
- Independent review must approve the exact combination, key validation, domain separation, encoding and failure behavior. The current composition is not X-Wing, standardized HPKE or a TLS hybrid. Real ML-KEM and successful roundtrips alone are insufficient.
- Reject malformed/unknown suites without downgrade. Handle ML-KEM implicit rejection and unusable X25519 outputs correctly. Retained private keys allow historical envelope recovery; no forward-secrecy or zero-access claim is made.

## Mathematical description

Let `P` be document bytes, `A` trusted resource context, `D` a random 32-byte DEK, and `n` a random 12-byte nonce.

```text
C = AES256GCM.Encrypt(D, n, P, A)
(s_pq, ct_pq) = MLKEM768.Encapsulate(PK_pq)
(e_sk, e_pk) = X25519.Generate()
s_x = X25519.Exchange(e_sk, PK_x)
H = canonical JSON {version, suite, key_version, ct_pq, e_pk}
K = HKDF_SHA256(s_pq || s_x, salt=SHA256(H),
                info="onesmarter:dek-wrap:v2\0" || A, length=32)
W = AES256GCM.Encrypt(K, wrap_nonce, D, H || "\0" || A)
```

The stored envelope contains `H`, `wrap_nonce`, `W`, `n`, and `C`. Both GCM outputs include authentication tags. During decryption, ML-KEM decapsulation and X25519 exchange recover `s_pq` and `s_x`; the same HKDF inputs recover `K`; authenticated decryption recovers `D` and then `P`.

This exact hybrid composition is project-specific and requires protocol review and independent test vectors. It is not represented as a standardized HPKE/TLS cipher suite.

## Rotation and old documents

`rotate_wrapping_key` creates a fresh version and moves the previous version to `decrypt_only`, in one organization-locked transaction. Old envelopes name their original version, so Ammar can still read Sara's old document. Rotation does not re-encrypt that document.

Optional rewrapping unwraps the existing DEK and wraps it using the new version. It preserves the original DEK, content ciphertext and content nonce byte for byte; it verifies the old content before committing. Tests check this explicitly. Rewrapping an S3 object still transfers/writes the envelope object; it does not imply zero I/O.

```powershell
.\.venv\Scripts\python.exe manage.py rotate_wrapping_key --organization <UUID> --reason "Scheduled rotation" --request-id <OPERATION_UUID> --expected-active <ACTIVE_KEY_UUID_OR_none>
.\.venv\Scripts\python.exe manage.py rewrap_keys --organization <UUID> --limit 100
.\.venv\Scripts\python.exe manage.py rewrap_keys --organization <UUID> --limit 100 --apply
```

Repeat batches until candidates is zero and all skipped counters are reconciled. Per-record `CryptoUnavailable` failures (including MFA envelopes without a service pin) increment `skipped_crypto_unavailable` and leave the entire record unchanged; later records continue and skips do not consume the successful-candidate batch allowance. The command reports legacy, invalid and crypto-unavailable skips and warns that migration is incomplete. The generic exception cannot distinguish a missing MFA pin from a temporary key-service outage: investigate before choosing trusted MFA re-enrollment or retrying after recovery. Dry runs count candidates without testing unwrap eligibility. Active-key changes and non-crypto storage/database failures still stop the run rather than hiding operational errors. Completed records remain usable. File rewrapping writes a new object before atomically changing its database pointer. Old file objects remain until an approved cleanup policy permits removal. No key deletion command is provided. Audit events record activation and successful rewraps.

Root-protector rotation and organization wrapping-version rotation are different operations. The synthetic service atomically re-protects all private records and its root header in one SQLite transaction, then switches the in-memory root. Failed transactions roll back. This serializes key operations and needs capacity testing. Existing encrypted backups still need their matching old recovery secret. Legacy KMS records, if discovered, are rejected; migration of such records requires a separately reviewed recovery plan before rollout.

If a DEK or old private key was compromised, merely rewrapping is insufficient to protect ciphertext the attacker already copied. Incident response may require new DEKs and content re-encryption, credential revocation and replacement of affected key hierarchies.

## Recovery and compatibility

Back up database references, private object versions, encrypted private material, version records and formats together; separately protect custodian recovery authority. A database backup without usable keys cannot restore documents. The current local root-loss/recovery tests are not evidence for a production custody design. Test real self-managed service sealing/restart, selected quorum or hardware recovery, root migration and isolated restoration before release.

Committed documents are retained on the same thread without automatic age-based deletion. Session/access expiry and revocation never trigger key or content deletion. Keep keys recoverable for all retained documents and backups; do not promise infinite durability. See [DATA_RETENTION.md](DATA_RETENTION.md).

Version 1 was an earlier synthetic AES-only format. Existing synthetic data can be read and explicitly migrated; it is never newly written. `ALLOW_LEGACY_SYNTHETIC_READS=false` disables those reads. Non-synthetic environments never allow v1. Unknown versions/suites do not fall back to classical encryption.

## PQ coverage limits

Version 2 executes actual ML-KEM-768 in the stored-data-key wrapping path. That alone does not establish PQ protection for browser/ingress, the future internal key-service connection, remote scanning, authentication or backup/recovery. Scope email credential risks separately. Verify required transport hops and reject silent downgrade; follow the coverage matrix in KEY_SERVICE_ARCHITECTURE.md. No badge or configuration boolean removes the production gate.

Algorithm/API references: [Cryptography ML-KEM documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mlkem/), [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html), and [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html). Installed interfaces were exercised locally; independent protocol/implementation evidence remains pending.


## 29 October review remediation and rollout

See [V2_REMEDIATION.md](V2_REMEDIATION.md) for exact status and test evidence.
Key mutations require an explicit backup directory. Configure independently operated off-host storage; a different local folder does not satisfy disaster recovery. Checkpoints verify both source and copied audit chains before publication. Current-root committed snapshots retain all seven days of history, the earliest available snapshot per UTC day through day 30, and at least the newest three regardless of age. Pruning pauses while root recovery verification is pending. Root rotation retains old-root copies until the offline new-secret unseal and restore drill succeeds; `.pending` files require separate reconciliation. All wrapping private versions remain in the current store and newest snapshot, so document retention is unchanged. `snapshot_cleanup_complete=false` immediately after rotation means recovery verification is still required; it does not imply rotation rolled back. Offline copies, recovery-proof artifacts, filesystem snapshots, SSD remnants and remote replica retention require a separate inventory and retirement procedure. See KEY_SERVICE_OPERATIONS.md for the authoritative candidate policy, capacity implications and production approval requirements.

Snapshots are prepared as `.pending` and published only after the live SQLite commit. A failed transaction removes its pending copy. A crash between commit and publication requires operator reconciliation against the live store; automatic restore refuses pending files. Restore checkpoints the destination WAL before atomic publication. Snapshot creation still copies the full audit history under the store lock; large-history performance and independent checkpointing remain release work.

The isolated key service now pins the current MFA data-key digest per enrollment context in its own database. A fresh data key replaces the pin; old application-database MFA enrollments are rejected. Rewrapping retains the same data key, so a failed application migration does not invalidate its previous wrapper. This does not protect against rollback of the entire key-service database or theft of application runtime credentials. Local-development mode does not provide this separate trust boundary. Existing service MFA envelopes without pins require trusted re-enrollment, not trust-on-first-read. A service update and application update are coordinated maintenance, not a blind restart.

### Trusted recovery of unauthenticated legacy content

1. Inventory affected records with the dry-run migration and preserve the originals, associated key versions and backups for investigation.
2. Obtain the original plaintext from its trusted owner/source; confirm provenance and content outside the untrusted legacy store. Do not decrypt-and-re-MAC old unauthenticated wrappers as proof of provenance.
3. For documents, the authorized sender/recipient re-submits the trusted original using the existing authenticated upload-and-reply flow. This runs validation, real scanning when configured, fresh envelope encryption and audit recording. Preserve the old record identifier in the operator incident record; do not overwrite historical submissions.
4. Recreate messages from the verified original source as explicit new submissions. Reset MFA through the privileged administrator workflow and emailed recovery link; issue fresh invitation/OTP notifications instead of importing old secrets.
5. Verify staff retrieval and new authenticated envelopes before closing each inventory item. The migration's skipped counters must be reconciled; there is no automated bypass or unsigned legacy-envelope conversion command.

### Local custody cutover — 30 October 2026

The local application now uses `KEY_PROTECTOR=key-service` and
`KEY_SERVICE_REQUIRE_PQ=true`. This independent transport setting permits the
synthetic loopback HTTP portal while requiring PQ mTLS for actual key operations;
production still requires the complete PQ transport profile. The old runtime
`wrapping.key` was moved into protected rollback custody, not destroyed.
The migration identity was revoked and the service restarted without synthetic
import enabled. The workload has wrap/unwrap/rewrap/status/version access only.

`backend/apps/core/custody_migration.py` performs an offline cutover with separate
maintenance and workload clients. Stop every writer and take consistent database,
object, key-store, policy and configuration backups first. It verifies local
plaintext before remote mutations, imports existing versions as decrypt-only,
creates a service active version if needed, and registers current authenticated
MFA DEKs through normal service wrap without changing their plaintext. File
ciphertexts are preserved. Database key references change only after all eligible
plaintext hashes match. This routine is for synthetic local migration, not an
unauthorized production key import route. It does not automatically edit env or
restart processes; operator recovery copies must be retained until verification.

Observed live cutover: one existing wrapping version imported, 11 readable
envelopes verified, and record counts unchanged (5 conversations, 8 messages,
4 attachments, 2 staff accounts, 5 recipient grants). Twelve pre-existing
unauthenticated legacy envelopes were preserved unchanged and remain rejected:
2 subjects, 3 bodies, 3 filenames, 3 file objects, and 1 MFA seed. They require the
trusted recovery procedure above; no origin authentication was fabricated.
The restricted local report and rollback backup are under
`.runtime/custody-backup-20261030-184112/` and are excluded from Git.

Live HTTP verification: unsealed download 200, sealed download 503, all 11
readable-envelope decryptions rejected when sealed, bulk decrypt rejected, then
unsealed download 200 with identical bytes and all 11 plaintext hashes unchanged.
The post-cutover key-store backup passed a restore drill using existing recovery
custody. Already delivered plaintext and in-flight requests that obtained their
DEK before sealing cannot be recalled. These local checks do not constitute the
independent cryptographic review or production off-host custody approval.

## Staff SMTP credentials
StaffSMTP.password_ciphertext uses the existing authenticated envelope with smtp-credential context bound to organisation and staff ID. Rewrap and custody migration include these records. Sealed key-service operation prevents SMTP credential decryption as well as protected-content access. APIs and audit events expose configuration metadata only.

Evidence bundles and timestamp receipts retain their original authenticated envelopes. Preserve the associated wrapping private-key versions and custody backups; regular DB/attachment rewrapping is not permission to retire archive keys. Evidence metadata and legacy organisation OTP SMTP credentials (no longer used for delivery) are included in envelope migration. See EVIDENCE_ARCHIVE.md.


SMTP credential verification, 31 October 2026: personal mailbox passwords are authenticated encrypted envelopes bound to organization and staff identity. The configured remote key service unwraps their data keys; a sealed service refuses new unwraps. Username/email remains routing metadata. SMTP backend close drops its password reference, including on close errors; Python does not guarantee zeroization of immutable strings, and sealing cannot revoke a password already released to an in-flight connection. No plaintext SMTP password is returned by settings APIs. A real disposable key-store regression verifies successful decryption, seal rejection for both notification and OTP paths, and recovery after unseal.

See [Security hygiene remediation](QA_SECURITY_HYGIENE.md) for recovery-code migration, purpose-separated verifiers and document integrity-key rotation.
