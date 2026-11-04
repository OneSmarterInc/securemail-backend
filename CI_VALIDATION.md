# RP-06 — complete CI validation

Verified 2026-11-04 (Asia/Calcutta). **RP-06 acceptance criteria met on the validation branch.**

- Fixed commit: `946ea0aae3cb60b22ff116420399cb8cbe84fc28`
- Branch: `codex/rp06-ci-green-20261104`
- Base: remote `main` at `192b01857192a67f0a03c995df26d3074c8a4071`
- [Successful complete workflow run 41785321549](https://github.com/OneSmarterInc/OneSmarter_Secure_Mail/actions/runs/41785321549)
- [Draft PR #2](https://github.com/OneSmarterInc/OneSmarter_Secure_Mail/pull/2), not merged
- Workflow: `Application checks`; event: `push`; conclusion: `success`; all eight jobs completed successfully on the same commit. Results were not assembled from different revisions or partial reruns.

## Repairs and scope

The module docstring precedes `import json as _integration_json` in `backend/config/settings.py`. Backend/scripts and frontend formatting are corrected. The mandatory APP_ENV follow-up and current security/portal/performance changes are included in the tested snapshot; it is not a formatting-only PR. The snapshot was based on the current remote tree to preserve the merged integration work. No .env, runtime keys, databases or credentials were published.

Both `ruff check backend scripts` and `ruff format --check backend scripts` pass locally and in the backend CI job. The format check reports 134 files already formatted. No security scan, vulnerability threshold, test assertion or production startup restriction was disabled to obtain a green result.

## Results from this run

| Job | Result | Evidence summary |
| --- | --- | --- |
| backend | Success | PostgreSQL-backed suite: 415 passed, 8 skipped; lint, formatting, Django system checks and migration drift passed |
| frontend | Success | Build, formatting and npm dependency audit passed |
| browser | Success | 39 browser tests passed through the isolated Compose deployment |
| pq-transport | Success | 8 real loopback transport/adapter checks; 41 key-service/transport/recovery tests passed, 1 skipped; component load had zero errors, p95 3.1 seconds |
| proxy | Success | 17 nginx/proxy/rate-limit tests passed |
| scanner | Success | 17 checks passed against the configured ClamAV fixture with signatures |
| python-dependency-audit | Success | Strict audit of application and test dependency locks passed |
| security-scanners | Success | Bandit completeness, repository secret scanning and HIGH/CRITICAL image vulnerability gates passed |

Skipped tests are not passes. This run is CI evidence on disposable infrastructure, not deployed production evidence, an independent cryptographic review, a real custodian recovery drill or approval to process confidential data. Production release gates remain enforced.

## Retained evidence

Full logs and metadata are kept locally in the ignored `.runtime/rp06-evidence/` directory:

- `run-41785321549.log` — full workflow logs.
- `run-41785321549.json` — exact run SHA, URL, job/step status and conclusion.
- `ruff-check.log` and `ruff-format.log` — local verification outputs.
- The fixed Git commit above is the authoritative source snapshot; later local candidate manifests are not evidence for this historical run.

SHA-256 of the full log file: `a66117edaeb0c13ea7022eacc71f9053c2bd9d6fdbfe37e7b8e97760198fae4d`.

This evidence report was written after completion. It does not change the tested commit. Main remains unchanged by this task; merge approval is separate.
