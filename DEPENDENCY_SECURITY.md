# Dependency hashes, image SBOMs and attestations

## Python artifact verification

`requirements.in` and `requirements-test.in` preserve the existing exact version set, including transitive pins. Their generated `.lock` files contain SHA-256 digests of non-yanked wheels published for those releases on PyPI. This is an equivalent hash-lock generation workflow; it does not automatically upgrade or resolve package versions.

Regenerate deliberately after reviewing dependency changes:

```text
python scripts/lock_dependency_hashes.py
python scripts/check_dependency_hashes.py
```

The generator retrieves release metadata over HTTPS from `pypi.org`, validates the requested version and hash shape, sorts/deduplicates wheel hashes, and finishes generation before replacing either lock. The trust boundary is the reviewed PyPI metadata at lock-generation time. Hashes detect differing artifacts during later installation; they do not certify that an approved package is nonmalicious. Review lock diffs and dependency provenance before approving them.

All application/test lock installations in Docker and CI use `--require-hashes --only-binary=:all:`. New or unpinned transitive dependencies, mismatched hashes and missing compatible wheels fail installation. Source distributions are disallowed to avoid an implicit, unhashed build-dependency installation. This means a new Python/platform combination may require reviewed wheel availability before it can build. No source-build fallback is provided.

The verification script installs both complete locks into a disposable directory without trusting already-installed packages, then proves that an incorrect hash and a modified wheel are rejected specifically with pip's hash-mismatch error. The `dependency-hashes` CI job additionally runs `--docker`: it builds both actual application Dockerfiles in disposable contexts containing an intentionally incorrect package hash. The job passes only when both builds fail for that exact reason, rather than an unrelated missing file/network error. Normal CI image builds provide the successful-install control. Evidence logs are retained for 14 days.

Audit-tool bootstrap commands (`pip-audit` and Bandit) remain separate version-pinned CI tooling; they are not runtime image dependencies or covered by these two application locks. OS packages remain governed by the pinned image bases and image vulnerability gates. Frontend dependencies retain npm's lock-file integrity checks.

## Image inventories and signed evidence

After all existing image security gates pass, `scripts/export_image_evidence.py` exports the exact backend, frontend and PQ images inspected by CI. A digest-pinned Trivy image creates an SPDX JSON inventory for each Docker image ID. A manifest binds the source commit, Docker configuration digest, image-archive SHA-256 and SBOM SHA-256. CI rejects missing, empty or oversized inventories and retains the archives, inventories, manifest and locks as the `scanned-image-evidence` artifact for 14 days.

On push events, a separate `image-attestations` job waits for every validation job. It downloads only the artifact from the same workflow run, then uses the commit-pinned official `actions/attest` action for:

- SLSA build provenance for the exact saved-image archive bytes.
- One signed SPDX SBOM attestation per image archive.

Only that job receives OIDC/attestation write permissions. Pull-request runs build and scan but do not receive signing permissions. No image is pushed to a registry. The attested subject is a Docker image **archive SHA-256**, not an OCI registry-manifest digest; Docker configuration digests are recorded separately in the manifest. A later registry-release pipeline must attest and verify its actual published manifest digest before deployment.

Download the `scanned-image-evidence` artifact from the matching run, then verify its files before loading them:

```text
gh attestation verify backend.image.tar --repo OneSmarterInc/OneSmarter_Secure_Mail
gh attestation verify backend.image.tar --repo OneSmarterInc/OneSmarter_Secure_Mail --predicate-type https://spdx.dev/Document
```

Also check the approved commit/workflow identity and manifest values; a valid signature on an unapproved branch is not release approval. Repeat for frontend and PQ archives. Record verification results with the deployment change record. Production gates remain unchanged.

References: [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/), [GitHub attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations), [official attest action](https://github.com/actions/attest), [Trivy SPDX generation](https://github.com/aquasecurity/trivy/blob/main/docs/guide/supply-chain/sbom.md).
