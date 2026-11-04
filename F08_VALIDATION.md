# F-08 dependency integrity validation

Validated on 2026-11-04 against commit `011f8d65ef13bd597b17315459f6d42ca0f2e1bb` on draft PR #2. This report was written after the run; it is not part of the tested commit.

- [Completed CI run: all 10 jobs passed](https://github.com/OneSmarterInc/OneSmarter_Secure_Mail/actions/runs/41792202942).
- [Draft PR](https://github.com/OneSmarterInc/OneSmarter_Secure_Mail/pull/2); not merged into main.

## Acceptance evidence

Both Python locks preserve 46 exact package versions and contain 389 approved wheel SHA-256 hashes. Application lock installs in Docker and CI require hashes and disallow source-distribution fallback.

The dependency-hashes job successfully installed the complete locks, rejected an incorrect hash, rejected a modified wheel, and built both actual application Dockerfiles with deliberately incorrect dependency hashes. Both negative Docker builds failed specifically on pip's hash mismatch error. Normal backend and PQ image builds passed on the same commit.

The backend suite reported **482 passed, 8 skipped**. Frontend, browser, proxy, scanner, PQ transport, dependency audit and security-scanner jobs passed. Existing security thresholds were retained. Six new hash-lock unit tests also passed locally.

## Image evidence

The security-scanners job exported the exact scanned backend, frontend and PQ images and generated their SPDX inventories. The signing job ran only after all validation jobs succeeded.

- [Build provenance for all three image archives](https://github.com/OneSmarterInc/OneSmarter_Secure_Mail/attestations/63469721).
- [Backend SBOM attestation](https://github.com/OneSmarterInc/OneSmarter_Secure_Mail/attestations/63469734).
- [Frontend SBOM attestation](https://github.com/OneSmarterInc/OneSmarter_Secure_Mail/attestations/63469746).
- [PQ image SBOM attestation](https://github.com/OneSmarterInc/OneSmarter_Secure_Mail/attestations/63469764).
- [Hash rejection logs](https://github.com/OneSmarterInc/OneSmarter_Secure_Mail/actions/runs/41792202942/artifacts/13303548216).
- [Image archives, SBOMs, locks and digest manifest](https://github.com/OneSmarterInc/OneSmarter_Secure_Mail/actions/runs/41792202942/artifacts/13303318949).

Artifacts expire on 2026-11-18. Full run metadata and logs are retained locally in `.runtime/f08-evidence/run-41792202942.json` and `.runtime/f08-evidence/run-41792202942.log` (ignored by Git).

Attestations bind saved Docker image archive bytes, not registry manifest digests. No image was published to a registry or deployed. Signature creation succeeded in CI; a separate consumer-side download and `gh attestation verify` drill was not performed. Follow `DEPENDENCY_SECURITY.md` to verify artifacts and approved workflow/commit identity before loading them. Independent cryptographic review and production release gates remain unchanged.
