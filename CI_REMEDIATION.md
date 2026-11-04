# CI remediation — 31 October 2026

- DeliveryJob.state now allows 32 characters, including the 21-character development_delivered state. Migration 0022 fixes PostgreSQL rejection; SQLite did not enforce this length.
- Disposable PostgreSQL transaction-test teardown temporarily disables only the no-TRUNCATE audit trigger. Mutation protection remains enabled during application tests; the override refuses non-test database names. The fixture now covers all transaction tests, including nginx integration.
- The HTTP host-routing regression replaces unsupported ssl_curve telemetry on stock nginx and captures startup stderr. The unmodified production TLS configuration remains checked separately in the built nginx image.
- PQ integration runs inside the same pinned Python/OpenSSL image as the candidate key service. Image build verifies support for X25519MLKEM768 before any test. No classical fallback is introduced on controlled internal hops.
- ClamAV readiness probes its configured Unix socket with clamdscan instead of the image's TCP-only health check. Failure diagnostics include daemon and health-check logs. The same socket health check is used in Compose.
- Browser tests follow current modal actions, optional attachment controls and document-table response schema. Disclosure text contrast is strengthened. React formatting is normalized without changing component behavior.
- The secret scanner's historical findings are confirmed false positives on a Django query filtering unused password-recovery invitations. The remediation note quoting that query also triggered the same detector. Only these exact fingerprints are ignored; credential detection remains active everywhere else.
- Reactivation regression requires fresh password/MFA enrolment before restored access while preserving ownership.

Local checks: 38 mocked-API browser tests passed, frontend build and formatting passed, Ruff and migration drift checks passed, secret history scan clean with reviewed exact exceptions. GitHub CI is required for PostgreSQL, built-stack browser, nginx, ClamAV and PQ transport results. None of these changes closes the independent cryptographic review or other production release gates.

ClamAV's default TCP health check is documented at https://docs.clamav.net/manual/Installing/Docker.html .


Container verification found high-severity Debian base-package advisories without fixes listed. Candidate Python runtimes now use pinned Alpine images and are revalidated through the same Compose and real PQ tests. The Trivy gate scans all three built images before reporting failure; no vulnerability ignores or severity downgrades are used.

Runtime images remove pip and ensurepip after dependency installation, including their unused vendored dependencies. The nginx runtime applies Alpine security updates during build. All three container scans passed on revision 4c10668, alongside PostgreSQL, real ClamAV, nginx and PQ transport checks. The recipient navigation contrast now has an Axe regression test. Browser assertions distinguish synthetic scanning (disabled health button) from the dedicated real-scanner job.

Local full backend result: 359 passed, 17 skipped; service-dependent evidence comes from CI, not these local skips. Keep the production release gates open.
