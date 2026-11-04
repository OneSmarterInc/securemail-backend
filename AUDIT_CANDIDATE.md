# RP-04 / RP-05 audit integrity candidate

Date: 2026-11-04. **Candidate — internal design decision 2026-11-04, independent review pending**.
[D1–D7](DESIGN_DECISIONS_2026-11-04.md) replace the previously open internal R1–R5
choices. They are not independent human approval. Production remains blocked.
See [the handoff](REVIEW_HANDOFF_2026-11-04.md) and
[mutable-field inventory](MUTABLE_FIELD_INVENTORY.md).

## Selection and compatibility

The separate `CandidateKeyStore` is selected by the CLI only when all three
process environment conditions hold:

```text
KEY_SERVICE_AUDIT_CANDIDATE=true
APP_ENV=development  (or test)
SYNTHETIC_MODE=true
```

Production, unset and other environments are rejected. The default remains
false. Candidate database metadata and root associated data prevent silent
opening by the legacy implementation. Existing stores are not automatically
migrated. No live environment file, store, service or recovery secret was changed.

The key-service CLI does not load the application's `.env`: provision these
settings explicitly in its process/service configuration. `--synthetic-only`
and existing escape-flag checks are still required; checkpoint transport has
no classical/HTTP escape flag.

## Implemented cryptographic profile for review

Keys are generated randomly, not derived from the root:

- `K_audit`: 32 random bytes, HMAC-SHA256.
- `K_sign`: Ed25519 seed, used for checkpoint signatures.
- A stable random `store_id` binds all authenticated audit bodies and checkpoints.
- Wrapped audit keys (including history) are stored in `meta.audit_keys`;
  `audit_key_id` identifies the current one. The signing seed is in
  `meta.checkpoint_key`; its public key is not secret.

Both secrets are AES-GCM wrapped under the root with canonical associated data
containing `purpose`, `store_id`, and `key_id`. Purpose strings are `audit-mac`
and `checkpoint-sign`. Root rotation rewraps them and preserves their identities.
Candidate roots use separate associated data containing
`purpose=candidate-audit-root-v2`, `store_id`, and `root_id`.

Audit bodies retain the existing SHA-256 `previous` link and add `audit_v=2`
and `store_id`, plus the protected `state_digest` on every MACed row. Existing append-only triggers remain. For each authenticated row:

```text
digest = SHA256(canonical_body_bytes)
mac = HMAC-SHA256(K_audit,
      ASCII("onesmarter:keystore-audit:v2") || 0x00 ||
      ASCII(decimal_sequence) || 0x00 || ASCII(hex_digest) || 0x00 ||
      ASCII(previous_authenticated_mac_or_64_zeroes))
```

`mac` and the audit `key_id` are separate columns. Audit-key rotation inserts
one row containing both the old-key MAC and `next_mac`, the new-key MAC over
the same sequence/digest using the old-key MAC as its preceding MAC. Subsequent
rows chain from `next_mac`. Historical keys stay wrapped and are verified.
This exact encoding/dual-proof rule is a candidate choice requiring review.

Checkpoint packets contain `record` and a base64 Ed25519 `signature` over
`b"onesmarter:keystore-checkpoint:v1\0" + canonical(record)`. The record contains:

```text
v, store_id, root_id, seq, head_digest, head_mac, audit_key_id,
checkpoint_key_id, event, issued_at_ns, previous_checkpoint_sha256,
previous_root_id, state_digest, sig_alg="ed25519"
```

`previous_root_id` is null except on a root transition. `head_mac` uses `next_mac`
at an audit-key transition. Checkpoint links hash the complete canonical signed
packet, including its signature. The public identity is pinned independently;
the service cannot enroll an identity by sending a request.

An explicit extension to the proposal binds protected key state through
`state_digest`. Without it, a writer could splice older authentic key-state
rows underneath a newer authentic audit history. Its exact candidate encoding
is SHA-256 of `b"onesmarter:keystore-state:v1\0"` followed by canonical JSON
containing sorted metadata pairs and ordered complete rows from `versions`
(ordered by id), `requests` (id), `mfa_current` and `current_deks` (context, or null when absent).
Metadata excludes only `seal_epoch`, `candidate_genesis` and
`candidate_pending_checkpoint`, which are volatile or self-referential.
Audit rows and the explicitly untrusted sealed spool use their separate rules.
Unseal/restore and readiness check this digest against the latest MACed event and the acknowledged checkpoint prefix. Only a transaction that
entered an authorized key-state mutation path can publish a changed state;
periodic export cannot bless a database writer's altered state. This extension
and its table/field coverage also require reviewer approval.

**Ed25519 is classical, not post-quantum.** Hybrid TLS protects the connection;
it does not turn a classical signature into long-term PQ evidence. D1 chooses Ed25519 internally with an explicit algorithm field; human review remains open. The S3 SDK adapter does not establish PQ negotiation. Signing-key rotation is deliberately
rejected until its cross-signing and separate custodian-confirmation protocol
is approved and implemented. Audit-key and root rotation are implemented.

## Sealed events and crash observations

Normal seal writes an authenticated seal row and requires a receiver
acknowledgement before completing. Memory references are cleared even on error.
Python does not provide guaranteed physical zeroization of immutable byte
objects; this is not a memory-forensics protection claim.

After an authenticated seal/genesis boundary, login/denial observations can be
written without a MAC. On unseal, a signed `sealed_gap_attestation` binds their
sequence range and head digest and labels them `trusted=false`. Missing MACs
outside such a boundary, on key operations, or with mismatched gap attestations
are rejected. Removing all MACs does not downgrade a candidate chain to v1.

A crash may leave no seal row. In that case, sealed login/denial observations
go to a bounded (1,000-entry), explicitly untrusted `sealed_pending` spool.
On successful unseal, a MACed observation row records those values with
`trusted=false` and drains the spool transactionally. This avoids retaining a
plaintext signing/MAC key solely to record sealed events. A full queue fails
logging rather than dropping observations silently.

D2 accepts this residual internally: a database writer can coherently alter unexported unsigned
observations before unseal. Signing their later observation does not prove
their original accuracy. The tests explicitly demonstrate this residual.

## External receiver and publication

The local append-only `CheckpointLog` / reference HTTP receiver is **test-only**:
APP_ENV must be test. Its SQLite triggers are not host-admin-proof WORM storage.
Tests exercise pinned identities, signature/link rejection and actual PQ/mTLS
via `backend/transport/recovery.py`; no AWS resources are provisioned.

D4 selects `s3_checkpoints.S3Publisher`: separate-account Object Lock COMPLIANCE,
SSE-S3, separate writer/read profiles and out-of-band pinned genesis. Writes use
If-None-Match on predecessor-hash object keys. Reads verify exact version retention
and SSE-S3. No deletion, KMS or retention-policy mutation calls exist. See the
handoff for permissions, transport and linear-traversal deployment limitations.
D5 requires six-year retention (at least the backup lifetime) and no pruning.

Checkpoints are required for unseal, seal, key mutations, root/audit rotation
and recovery-state changes. They are also attempted after 100 audit rows or
5 minutes while unsealed; the server timer covers idle periods. Receiver outages
set export-pending status and use bounded 30-second periodic retry backoff.

- Key mutations fail closed during receiver outage.
- Wrap/unwrap/rewrap continue with MACed state commitments; scoped mutable-field
  changes also take a local encrypted snapshot. External freshness remains limited
  until export, as documented below.
- Unseal/restore require the receiver unless the mTLS-authenticated custodian
  session supplies a 20–500-character reason. CSRF and operation permissions apply.
  The CLI has no unauthenticated override switch.
- Overrides add a MACed integrity_override event and report unverified_override.
  The app's read_status exposes it and ready() is false, so document submission/
  delivery is disabled. Service-level wrap/unwrap availability is separate.
- Seal clears override authorization even on failure. The pending event remains
  alertable until successful export. Restart conservatively reports any prior
  override as unverified until external verification/export succeeds.
- Corrupt signatures, changed identity and chain conflicts cannot be overridden.
- Optional KEY_SERVICE_CANDIDATE_RESTORE_DIR enables the custodian copy-restore
  form. It restores the configured store into a new UUID-named sealed copy; it
  does not activate a store or accept arbitrary browser-supplied filesystem paths.

## Remote acknowledgement versus local commit

A remote log and local SQLite cannot be committed atomically. Before sending,
the candidate writes a verified, fsynced encrypted `.pending` snapshot containing
the proposed signed packet. It then asks the receiver to append. The local
transaction commits only after acceptance. Any ambiguity after transmission
retains that snapshot, clears the live root and requires reconciliation.

If the receiver accepted but local commit failed or the acknowledgement was
lost, the old live store is behind the remote head and cannot unseal. This is
intentional fail-closed behavior, not a successful rollback. Recovery must
restore the retained `.pending` image whose packet exactly equals the latest
externally acknowledged checkpoint. If that evidence is lost, do not bypass
the anchor to regain availability. No two-phase commit or automatic conflict
resolution is claimed.

Normal restore verifies a copy without appending audit events or advancing the receiver
head. Outage override restore records its MACed exception in the sealed copy; it never advances the remote head during the drill. This prevents a restore drill from forking the live service's audit log.
It validates root/private records, authenticated history, pinned identity and
external freshness before publishing a standalone sealed database.

## Freshness limits

Acknowledged checkpoint prefixes are protected against coherent database-only
rewrites, stale restores and truncation below the external high-water mark.
Unsealed operations also compare against the in-memory verified checkpoint so
a live rollback cannot discard that already-observed prefix during an outage.

**T3 is only partially covered:** a valid tail that has never been exported may
be truncated without detection after restart. A MAC chain proves authenticity,
not that a later row ever existed. Covering every tail requires synchronously
exporting every audit event or an independent durable counter/witness; this
changes the proposed wrap/unwrap outage availability tradeoff. The regression
suite includes an explicit residual test, rather than falsely asserting full
T3 coverage.

As in the proposal, live-root compromise can forge new MACs/signatures; it cannot
delete records already retained by a separately administered receiver. Recovery
secret plus store compromise remains out of scope. Full-history verification
currently costs O(number of rows) on key use: suitable for candidate evaluation,
not a performance-approved production design.

## Synthetic operator workflow

All commands below are test-fixture commands: APP_ENV=test and the other two
candidate settings above are mandatory. They do not deploy the D4 S3 receiver.
Use synthetic data and a stopped/exclusively owned source store. Recoverable
secrets are prompted, never passed as CLI arguments.

1. Create a new candidate store with the existing `init` flow and
   `--candidate-enrollment PATH`; or copy-migrate a v1 store:

   ```text
   python -m backend.keyservice migrate-audit-candidate --source OLD_STORE --store NEW_STORE --backup-directory BACKUPS --trusted-checkpoint CUSTODIAN_V1_ANCHOR --enrollment ENROLLMENT_JSON
   ```

   V1 migration checks the independently retained v1 anchor, preserves the
   source, and writes an authenticated genesis binding the legacy prefix.
   Legacy rows remain SHA-only; the migration does not retroactively prove
   their truth. The first signed checkpoint is registered before any unseal.

2. Transfer the public enrollment document through the custodian's independent
   channel. Verify its store identity/public-key fingerprint outside the key
   host. On the separately administered receiver:

   ```text
   python -m backend.keyservice.checkpoint_receiver init --log RECEIVER_DB
   python -m backend.keyservice.checkpoint_receiver enroll --log RECEIVER_DB --enrollment ENROLLMENT_JSON
   python -m backend.keyservice.checkpoint_receiver serve --log RECEIVER_DB --policy RECEIVER_POLICY --ca CLIENT_CA --cert RECEIVER_CERT --key RECEIVER_TLS_KEY --host RECEIVER_BIND --port 9444
   ```

   Enrollment requires administrator filesystem access; it is not exposed over
   HTTP. The enrollment document is public but trust-sensitive.

3. Provision `KEY_SERVICE_CHECKPOINT_CONFIG` on the key host, independently of
   mutable store metadata. Its JSON has exactly these fields:

   ```json
   {"store_id":"CUSTODIAN_VERIFIED_UUID","public":"CUSTODIAN_VERIFIED_BASE64_PUBLIC_KEY","url":"https://receiver.example:9444/v1/checkpoints/CUSTODIAN_VERIFIED_UUID","ca":"/custody/receiver-ca.pem","cert":"/custody/publisher.pem","key":"/custody/publisher.key"}
   ```

   Receiver policy: `{"identities":{"CERT_SHA256":{"stores":["STORE_UUID"],"publish":true}}}`.
   A read-only custodian identity uses `publish:false`. Use separate TLS
   identities from the portal and restrict private file permissions.

4. Start the existing `serve` command with its normal policy/TLS/backup arguments
   and `--synthetic-only`. The maintenance portal unseal now uses candidate
   checks. Offline audit-key rotation:

   ```text
   python -m backend.keyservice rotate-audit-key --store STORE --backup-directory BACKUPS
   ```

5. Restore to a new path with `restore --backup BACKUP --destination NEW_STORE`.
   Candidate recovery uses the configured receiver, not a stale local anchor.
   Only for an acknowledged-but-uncommitted packet, add
   `--reconcile-candidate-pending` and point at the retained `.pending` file.
   Stop the original owner, verify the destination and update its explicit
   backup path before starting it. Do not run two owners of one store identity.

If enrollment export was interrupted, `candidate-enrollment --store STORE
--destination NEW_ENROLLMENT_JSON` reproduces the original public genesis.
It never enrolls that identity automatically.

## Internal decisions and remaining independent review

| Decision | Current candidate behavior | Status |
| --- | --- | --- |
| D1 algorithms | HMAC-SHA256 + Ed25519 with sig_alg; signing-key rotation rejected | Internal decision only; human review pending |
| D2 sealed observations | Explicitly untrusted gaps and bounded crash spool | Residual accepted internally; human review pending |
| D3 outage | Mutations fail; wrap/unwrap/rewrap continue; authenticated reason-bound override for unseal/restore | Local tests; human review pending |
| D4 receiver | Separate-account S3 COMPLIANCE adapter; local log test-only | Real deployment/IAM/WORM evidence pending |
| D5 frequency/retention | 100 rows/5 minutes and lifecycle checkpoints; six years minimum, no pruning | Capacity and deployment enforcement pending |

Reviewer name, date and reviewed commit: **not supplied / not signed**.

## Historical local verification evidence

The final full local regression run passed **534 tests, with 18 skipped**, after
the protected-state commitment and splice regressions were added. Log:
`.runtime/rp04-rp05-final-regression.log`. Skipped tests remain unverified in
that run; its SQLite/local environment is not PostgreSQL or production proof.
SHA-256 hashes of the tested audit/transport implementation, tests and CI
selection are retained in `.runtime/candidate-audit-source-manifest.json`.

The final related suite passed **77 tests** on the local Python 3.15 / OpenSSL
3.5.9 runtime with actual loopback hybrid TLS and temporary mTLS identities.
This includes F-11, candidate audit, checkpoint transport, legacy checkpoint
acceptance and snapshot-retention regressions. Log:
`.runtime/candidate-final-state-hybrid.log`. Ruff lint and formatting checks
passed for backend/scripts. These are local synthetic results, not independent
review, new GitHub CI evidence or proof of an off-host receiver deployment.

Key regression coverage:

| Regression | Observed behavior |
| --- | --- |
| Coherent SHA rewrite / stripping MACs | Unseal refuses; root cleared |
| Older snapshot / published-tail truncation | External anchor refuses |
| Deletion and renumbering | MAC chain refuses |
| Authentic audit plus older key-state rows | State commitment refuses |
| Periodic export after state tampering | Refuses to sign and seals |
| Root and audit-key rotation | Old authenticated rows/document remain usable |
| Lost key/root-rotation acknowledgement | Retained pending image reconciles against exact external packet |
| Interrupted copy migration | Transaction rolls back schema; source preserved |
| Receiver unavailable | Wrap/unwrap/rewrap continue; mutations fail; unseal/restore need explicit authenticated override |
| Forged signatures / validly signed fork / old replay | Receiver refuses |
| PQ/mTLS connection / unallowlisted CA-signed client | Valid traffic succeeds; unauthorized client refused |
| Sealed observation rewrite / never-exported tail removal | Explicit residuals reproduced, not falsely marked protected |

Reproduction (isolated synthetic process environment):

```powershell
$env:APP_ENV='test'
$env:DJANGO_READ_DOT_ENV='false'
$env:MAIL_PROVIDER='development'
.venv\Scripts\python.exe -m pytest -q
# Actual transport drill requires the separately provisioned hybrid runtime:
$env:RUN_PQ_TRANSPORT='1'
.runtime\pq-python315\python.exe -m pytest backend/tests/test_checkpoint_transport.py backend/tests/test_candidate_audit.py backend/tests/test_f11_escape_flags.py backend/tests/test_security_acceptance.py backend/tests/test_snapshot_retention.py -q
```

The CI PQ job now includes the candidate/transport regressions in its selection;
that workflow change has not been run remotely in this task.

## D1–D6 profile compatibility

The exact candidate profile is internal-2026-11-04-d1-d6. Older experimental
candidate stores are rejected rather than silently upgraded. Explicit legacy v1
copy migration remains supported; preserve the source and its custody material.
Current results are recorded in D1_D6_VALIDATION.md; earlier counts in this document
describe earlier working-tree revisions. F-07 has not started because D7 requires
these changes to be merged and tested first.
