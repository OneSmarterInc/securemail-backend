# Security remediation handoff

Candidate — internal design decision 2026-11-04, independent review pending.

The owner supplied [D1–D7](DESIGN_DECISIONS_2026-11-04.md); Claude's internal
design decisions do not satisfy RELEASE_GATES P0-5. Item 13 remains OPEN.
The current working tree is not a frozen reviewer or CI commit.

| Item | Current disposition | Required external evidence |
| --- | --- | --- |
| 9 old-root retirement | Same-host drill no longer authorizes deletion; independently signed remote-copy and clean-machine restore evidence required | Real remote copy, independently provisioned signer identities and clean-host drill |
| 10 mutable-field rollback | Scoped candidate current-DEK ledger; see MUTABLE_FIELD_INVENTORY.md | Human review and deployed checkpoint protection |
| 11 documentation | Design record, inventory, repository instructions and evidence corrections supplied | Current-revision CI run remains pending |
| 12 F-07 | NOT STARTED: D7 requires RP-04/RP-05/item 10 merged and tested first | Separate v3 change, migration and review |
| 13 independent review | OPEN; production block unchanged | Qualified human, signed report against immutable commit, remediation/retest and owner sign-off |
| 14 envelope vectors | Frozen complete v2 envelope vectors plus cross-library local verification | Independently maintained implementation/team verification; v3 vectors after D7 |
| 15 deployed PQ | Local actual-handshake tests are distinct from deployed endpoints | Image digest and handshake/downgrade evidence through each real load balancer |
| 16–18 backups/custody | Guardrails and synthetic recovery tests only | Off-host target, coordinated fresh-host restore, real custodian seal/unseal/rotation/lost-secret drills; RTO/RPO |
| 19 scanner | Existing adapters/tests do not prove deployed antivirus behavior | Deployed clean/EICAR/outage/oversize/nested/encrypted corpus |
| 20 capacity | No capacity claim from unit tests | Approved SLOs and staging read/write/rotation/outbox load evidence |
| 21 alerts | Existing failure signals and candidate override/export logs available | Real paging destination, owners, delivery and acknowledgement drill |
| 22 host hardening | Not performed on a live host | Swap/core policy, private 8443 firewall, socket permissions and least-privilege service proof |

## D4 checkpoint receiver deployment

Provision a separate AWS account and Object Lock bucket with default COMPLIANCE
retention of at least six years, SSE-S3 and versioning. No KMS dependency. Preserve
checkpoints at least as long as any key-store backup; never automatically prune.
Six years is the owner-selected policy; this document is not legal certification.

Use separate independently reviewed credential profiles: writer PutObject only;
reader GetObject/GetObjectRetention/GetBucketObjectLockConfiguration. Deny writer
deletion, retention/policy changes and unconditional overwrites. Enroll the public
signing identity and signed genesis out of band; the key service cannot enroll.
Check actual IAM principal/account identities: different profile names alone
do not prove separate principals. SDK account-owner checks are defense in depth.

`KEY_SERVICE_CHECKPOINT_CONFIG` points to JSON with fields `provider: "s3"`,
`writer_profile`, `reader_profile`, `region`, `bucket`, `receiver_account`,
`application_account`, `public` and `genesis` (the complete signed packet).
Do not place AWS credentials in that file. The reader starts from the pinned
`key-checkpoints/<store_id>/genesis.json` and follows immutable predecessor-hash
keys. Traversal is linear and capped at 100,000 checkpoints: review indexing and
capacity before deployment; this adapter is not a production scaling claim.

S3 SDK HTTPS is not verified PQ transport by this implementation. The test-only
reference HTTP receiver uses the existing verified PQ/mTLS recovery transport.
The production S3 transport profile remains a review/deployment gate, not an
implicit claim of identical PQ coverage.

## Retirement evidence and restore

`verify-root-recovery` without remote evidence runs a local drill and retains all
old-root snapshots. To authorize retirement it additionally needs
`--off-host-backup <downloaded-copy>` and `--recovery-evidence <signed-json>`.
`KEY_SERVICE_RECOVERY_TRUST` names separately administered public-key/host trust
configuration. `backend/keyservice/recovery_evidence.py` defines the strict
receipt and restore record schemas; synthetic examples are in its regression
tests. No application command issues trusted evidence to itself.

Both issuers must attest the same root and exact downloaded SHA-256, valid time
window, approved separate receiver/restore hosts and representative document
verification. The restored private versions must match the live store before
deletion. A valid signature proves what its issuer attested; operators must
establish actual host independence and document checks.

## Operator execution checklist

1. Freeze a source commit and dependency/image evidence. Hand over the protocol,
   candidate profile, probes and items 7/8/10/12 to the human reviewer.
2. Provision isolated staging, receiver roles and independently held recovery
   material. Verify every real endpoint with `scripts/verify_pq_endpoint.py`
   through its actual ingress; retain negotiation and downgrade output.
3. Restore PostgreSQL, encrypted files, key snapshot, policy and PKI together
   on a fresh host. Verify representative document integrity and record RTO/RPO.
4. Run custodian, scanner and approved load scenarios. Capture failures as well
   as successes; do not substitute local mocks for deployed evidence.
5. Page on audit_integrity=failed, unverified_override/export pending, archive
   lag, key_service_denial_audit_unavailable and sustained login failures.
   Test routing and acknowledgement; never put keys/content in alert payloads.
6. Inspect swap/core settings, private listener/firewall rules and Unix/clamd
   socket permissions. Retain configuration and negative-access evidence.

## Sponsor sign-off — still unsigned

| Item | Decision required | Owner / date / evidence |
| --- | --- | --- |
| 23 | Quorum or HSM custody; no ad-hoc secret sharing | Pending |
| 24 | Explicit recipient classical TLS fallback risk or hybrid-only policy | Pending |
| 25 | PostgreSQL, Redis, SMTP and checkpoint SDK transport scope | Pending |
| 26 | Authorized Nophi plaintext email/attachment egress | Pending |
| 27 | Long-lived recipient links plus mailbox OTP; mailbox compromise and guessing risk | Pending |
| 27 supplemental | Mutable-field/key-store rollback before candidate deployment, unexported tails and custodian override freshness loss | Pending |

Do not record “150 guesses/day” as a proven strict upper bound: token-bucket
initial capacity and refill, issuance limits, identity/IP scopes and per-code
attempts must be assessed together. A compromised mailbox can obtain valid OTPs
without guessing. D2 separately accepts unsigned sealed-observation risk as an
internal decision; it does not sign the unresolved sponsor rows above.
