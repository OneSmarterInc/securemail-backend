# Internal encryption review — 2026-10-28

**Disposition: not approved for production.** This is an internal code review and synthetic test exercise, not an independent cryptographic audit, certification, penetration test, or proof of the hybrid construction. Keep the existing real-data/startup restrictions.

Scope: document envelopes, OSM-v2 protocol, Django key-service adapter, sealed SQLite key store, HTTP/mTLS service and custodian authentication, rotation/recovery, migration code, dependency installation and relevant tests. No live AWS environment, real documents or email credentials were used. The initial review did not modify runtime code; the subsequent remediation below does.

## Remediation status — 2026-10-28

All four reproduced code defects have been addressed. The original observations below are retained as historical evidence, not descriptions of the repaired behavior.

| Finding | Implemented repair | Remaining boundary |
| --- | --- | --- |
| ER-01 | v1 local-key reads require `KEY_PROTECTOR=local-development`, regardless of the legacy flag | Convert legacy records offline before service cutover; retain backup recovery keys |
| ER-02 | OS-held exclusive service ownership; transactional seal epoch invalidates other store objects on their next operation/status | Single local-filesystem service only; no replication, rollback-resistant epoch, or guaranteed memory zeroization |
| ER-03 | Django requests active-only metadata; history is cursor-paginated in pages of at most 100 | Concurrent rotations do not provide a historical snapshot across pages; retain old keys |
| ER-04 | Unseal verifies sequence continuity, each body hash and previous-hash linkage; failures clear live root references and expose `audit_integrity=failed` | External authenticated checkpoints and rollback detection remain production gates |

The OS releases ownership after termination; the lock file is deliberately retained. Request threads finish before normal server close releases ownership. The seal epoch is stored in the same SQLite transaction as the seal event and is checked before subsequent key operations. No encryption format or document ciphertext was changed.

## Original reproduced findings (before remediation)

### ER-01 — Medium: legacy envelopes bypass the selected service boundary

Location: `backend/apps/core/crypto.py:82` and `backend/config/settings.py:104`.

The v1 branch unwraps with the local key before checking `KEY_PROTECTOR`. With synthetic mode and legacy reads enabled (the development default), selecting `key-service` does not make legacy reads depend on that service. A reproduction returned Sara's synthetic plaintext while the service accessor was configured to raise an unavailable error.

This requires a valid legacy envelope and its original local root. It is not a v2 downgrade attack, does not forge authentication tags, and does not bypass staff authorization. Nevertheless, a custodian cannot treat sealing the service as stopping all document decryption during this configuration/migration period.

Remediation: reject local legacy reads in the normal service-mode application; provide a separately authorized, explicit offline migration path. Inventory legacy records and retained backups before removing their recovery keys. Test sealed/unavailable service behavior for every supported envelope version. Merely changing the default flag is weaker than enforcing the boundary in code.

### ER-02 — Medium: sealing is local to one store instance

Location: `backend/keyservice/store.py:51`, `:140`, `:156`; service startup in `backend/keyservice/__main__.py`.

Two `KeyStore` objects can open and unseal the same SQLite store. After the first reports sealed, the second still unwraps the existing DEK. SQLite transaction serialization does not revoke an in-memory root in another instance. The test reproduces this with two objects; a separate multi-process deployment was not exercised.

The documentation requires one service process per store, but startup does not enforce ownership. This becomes an operational security failure if duplicate processes are started, for example during restart/deployment or behind a load balancer. The supported single-instance path does seal correctly.

Remediation: enforce exclusive service ownership of a store for the process lifetime, with crash-safe release and startup failure for a second owner. If replicas are needed later, design an explicit coordinated seal/revocation protocol rather than sharing the SQLite file. Add actual multi-process startup/restart tests; do not confuse Django's worker count with key-service replication.

### ER-03 — Medium: retained rotation history eventually prevents active-key lookup

Location: `backend/apps/core/keyring.py:209`, `backend/keyservice/store.py:184`, `backend/keyservice/client.py:44`.

Each active-key lookup retrieves every historical public key. The client rejects responses larger than 1 MiB. With 600 actual versions for one synthetic organization, the serialized response was **1,102,808 bytes**, exceeding the **1,048,576-byte** limit. Service-mode encryption and operations that resolve the active key consequently fail. Direct old-envelope unwrap does not require this listing and is not shown to fail by this test.

Remediation: add a bounded active-key endpoint and use it on encryption/rotation paths; paginate historical listings separately. Preserve old decrypt-only versions for retained documents. Increasing the response limit only postpones the failure. The current listing also decrypts every historical private record to derive public metadata, adding avoidable work.

### ER-04 — Medium assurance gap: unseal accepts corrupted audit history

Location: `backend/keyservice/store.py:118`, `:140`.

Unseal verifies private records but does not verify existing audit hashes, links or a trusted checkpoint. In a temporary synthetic store, removing the update trigger and changing an earlier audit body without updating its hash did not prevent unseal.

This models a modified backup or privileged store writer, not an ordinary portal user. SQLite triggers still block normal update/delete operations. No claim is made that an attacker with full control of a running host can be defeated by a local hash chain. This confirms an already documented external-checkpoint gap rather than a new bypass of portal permissions.

Remediation: verify chain integrity before accepting restored stores and expose a monitored integrity-failure state; retain authenticated checkpoints outside the store's writable trust boundary and implement rollback detection/reconciliation. A local hash check alone cannot detect a complete malicious rewrite or rollback to a previously valid snapshot.

## Additional release blockers and limitations

- **Hybrid approval remains open.** The project-specific HKDF combiner and authenticated transcript need independent review. ML-KEM and X25519 primitives do not make the surrounding format a standardized hybrid protocol. Review recipient-key binding, domain separation, malformed-input handling, implicit rejection, security claims and version migration. [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) specifies ML-KEM; [NIST SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final) addresses KEM use and combinations; [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) specifies X25519.
- **PQ transport now has an enforced candidate profile; deployment coverage remains open.** Subsequent work added PQ-only negotiation and group verification, key-service/custodian enforcement, scanner and recovery adapters, and a candidate HTTPS-edge configuration. Real local tests cover hybrid/downgrade behavior and adapters; see [PQ_TRANSPORT.md](PQ_TRANSPORT.md). Development mode is still explicitly separate. Actual ingress, scanner and recovery deployment evidence and full threat-model approval remain required.
- **Dependency provenance is incomplete.** Base images are now pinned by digest and dependency locks carry artifact hashes with --require-hashes installation (see F08_VALIDATION.md). These mechanical controls do not complete independent provenance review. `pip check` passing establishes dependency compatibility only. Require reviewed artifact provenance, hashes, image digest/SBOM and current vulnerability triage before release. This review did not complete a vulnerability advisory audit. Educational `kyber-py` remains test-only.
- **Software custody has limits.** Unsealed roots/private material can exist in Python memory; reliable zeroization is not guaranteed. Privileged host access can defeat software-only custody. Recovery secrets, TLS keys, dump/swap protection and custodian devices require deployment controls and drills. Old backups can require old recovery secrets after root rotation.
- **Application trust is intentional.** Django receives temporary DEKs and plaintext. The application migration path authenticates document ciphertext and rewraps through Django; it does not use only the service-native rewrap endpoint. This is not zero-access encryption, and sealing cannot recall plaintext or keys already obtained by another process.
- **Audit failure monitoring needs evidence.** Denial logging catches and suppresses storage errors in `server.py:285`. Access remains denied, but an independently observable alert is needed to avoid silent loss of security events.

## Positive evidence and tests

The selected suites exercise actual ML-KEM, published primitive vectors, two-direction compatibility using different test implementations, strict envelope parsing, tamper/context rejection, sealed service behavior for v2, mTLS/custodian authorization, concurrent rotation/read operations and encrypted backup/root recovery. These are useful engineering checks, not independent approval or exhaustive cryptanalysis. Migration code retains old ciphertext objects and changes database pointers transactionally; coordinated production recovery still needs a drill.

`backend/tests/test_encryption_review.py` now contains passing regression tests with no expected-failure markers. Coverage includes blocked legacy reads, cross-instance seal invalidation, actual subprocess ownership/crash release, 600-version active lookup and complete pagination, scope/parameter rejection, and audit body/link/sequence/JSON corruption, including an already-unsealed root. The rotation test may take longer on slow disks.

Reproduce from the repository root with a fresh temporary directory:

```powershell
$reviewTemp = Join-Path (Get-Location) ('.runtime/review-' + [guid]::NewGuid().ToString('N'))
.venv\Scripts\python.exe -m pytest backend/tests/test_encryption_review.py backend/tests/test_crypto.py backend/tests/test_crypto_vectors.py backend/tests/test_keyservice.py -q -rx --tb=short --basetemp=$reviewTemp
```

The HTTPS tests require loopback socket access. An initial sandbox run blocked those connections (WinError 10013); that was an environment restriction, not a cryptographic failure. Browser coverage is opt-in and is not part of this review run.

Original review run: **48 passed, 1 skipped, 4 expected failures**. A separate `--runxfail` run reproduced all four assertions as failures. Initial remediation verification: **56 passed, 1 skipped**, with no expected failures. Additional corruption and endpoint-pagination coverage was subsequently added. Ruff passed. The original `pip check` reported no broken requirements; this is not vulnerability clearance.

Full regression run after remediation and expanded tests: **102 passed, 10 skipped**, in 92.95 seconds, with no expected failures. Skipped environment-dependent/opt-in tests are not counted as verified deployment evidence. Formatting and lint checks passed for all changed Python files.

## Remediation order

1. Completed: enforce the service boundary for legacy data and exclusive key-service ownership.
2. Completed: bound active-key lookup independently of retained history.
3. Local audit verification completed; independent checkpoints, rollback detection and deployed failure alerts remain open.
4. Freeze the independently reviewed hybrid profile, verify mandatory PQ transport and complete dependency/custody evidence.
5. Regression tests no longer use expected-failure markers. Complete real deployment recovery/migration drills before seeking release approval.
