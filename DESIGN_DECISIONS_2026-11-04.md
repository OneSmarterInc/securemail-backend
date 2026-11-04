# Design Decisions — RP-05, RP-04, Item 10, F-07

Date: 2026-11-04. Decided by: Claude (AI design reviewer), at the request of the product owner.

**Status of this record.** These are binding engineering decisions, so implementation can proceed. They do **not** count as the independent cryptographic approval in RELEASE_GATES.md P0-5 (fix list item 13). That review needs an independent, qualified human reviewer who signs a report against an immutable commit. The production startup block and the synthetic-only warning stay in place. Label all work in this record "Candidate — internal design decision 2026-11-04, independent review pending".

---

## D1 (R1) — Algorithms

- **Audit row MAC:** HMAC-SHA256 with `K_audit`, as in proposal Section 3.
- **Checkpoint signature:** Ed25519 with `K_sign`.
- Add `"sig_alg": "ed25519"` to every checkpoint record, so ML-DSA (or a hybrid of Ed25519 and ML-DSA) can be added later without a format break. The receiver must reject any `sig_alg` it does not know.
- Rationale: checkpoints must detect rollback in the near term. A quantum forgery of checkpoints is a long-horizon threat, and the agility field covers it. Do not add ML-DSA now: it adds a dependency and review surface, and blocks nothing.

## D2 (R2) — Events written while sealed

- **Accept the residual risk.** Rows written while sealed carry no MAC and are protected by the SHA-256 chain plus the checkpoint taken at seal time.
- Do **not** add an always-available signing key on the host.
- Change the seal order as the proposal says: write the seal row with a MAC, publish the checkpoint, then clear the keys.
- Rationale: no key operation can happen while sealed. The only rows at risk are login and denial events. An unwrapped on-host key would weaken protection for every row.

## D3 (R3) — Checkpoint receiver outage

| Operation | Receiver down |
| --- | --- |
| Key mutation (rotate, import, root rotation, audit-key rotation) | **Refuse** (fail closed) |
| wrap / unwrap / rewrap | **Allow**; rows queue; the next checkpoint covers them |
| Unseal | **Refuse**, unless a custodian override is given |
| Restore | **Refuse**, unless a custodian override is given |

Override rules:

- The override needs the custodian session plus a typed reason of at least 20 characters.
- It writes an `integrity_override` row with a MAC.
- It sets `audit_integrity="unverified_override"` in status, which `document_service.ready()` must report.
- The override expires at the next seal.
- The override row must be exported once the receiver returns. Raise an alert until it is exported.

## D4 (R4) — Receiver platform

- **S3 Object Lock in COMPLIANCE mode, in a separate AWS account** from the application account.
  - The key-host identity holds `s3:PutObject` only. It does not hold delete, `PutObjectRetention` or bucket-policy rights.
  - Add read access for the latest checkpoint through a separate read-only role.
- This uses S3 only, not AWS KMS, so it fits the no-KMS rule. Use SSE-S3.
- Reuse the existing Object Lock archive adapter pattern.
- **Owner action:** the account itself must be created and its policy reviewed by OneSmarter. Until then, use a local append-only directory fixture **in tests only**.

## D5 (R5) — Frequency and retention

- **Publish a checkpoint on:** every key mutation, seal, unseal, root or audit-key rotation, and every 100 rows or 5 minutes while unsealed, whichever comes first.
- **Retain checkpoints for 6 years.** This matches HIPAA documentation retention. It must also cover the longest key-store backup retention. The sponsor may extend it.
- Checkpoint storage must never be pruned automatically.

## D6 — Item 10, rollback of fields updated in place

- **Approved as scoped:**
  - Inventory first.
  - Generalize the MFA "current DEK digest" table in the key service to only the contexts in the inventory.
  - Unwrap of those contexts refuses any DEK that is not current.
- The table is covered by the D1–D5 MAC chain and checkpoints. Ship it in the same candidate release as RP-05.
- Insert-only records (messages, attachments) are excluded once the inventory confirms they are insert-only.

## D7 — F-07, binding recipient public keys in the KDF

- **Approved for a new suite after RP-05 lands:** `OSM-v3-MLKEM768-X25519-HKDFSHA256-AES256GCM`.
  - KDF input adds `pk_x` (32 B) and `SHA3-256(ek)` to the salt hash input, along with the header.
  - Domain label: `"onesmarter:dek-wrap:v3\0"`.
- v2 becomes decrypt-only. Migrate with service-native rewrap.
- Produce known-answer vectors for v3 from an independent implementation (fix list item 14).
- Do not start this before RP-05, RP-04 and item 10 are merged and tested.

---

## Order of implementation

1. RP-05 + RP-04 (D1–D5), with the local append-only test fixture.
2. Item 10 (D6).
3. Probe tests RP-04 and RP-05 pass; remove their xfail marks. Add the tests in proposal Section 9.
4. F-07 (D7) as a separate change.

## Still open (not decided here)

- Item 13: an independent human cryptographic reviewer and a signed report.
- Separate AWS account for the receiver (D4), staging host, alert destination, and custodian names.
- Quorum or HSM custody (fix list item 23).
