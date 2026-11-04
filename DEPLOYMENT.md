# Deployment handoff


> Scope update — 2026-11-04: the owner removed antivirus from the product. Uploads undergo file-type/size validation, authorization, encryption and integrity checks; no malware verdict is produced. Historical scanning results below do not describe current functionality. Other release gates remain.


## Implemented portal boundary



- Staff/admin UI: `/staff/` (the root URL remains a compatible staff entry point).

- Recipient UI: `/recipient/#/invite/<opaque-token>`. A recipient without a link sees instructions, not staff login.

- New recipient invitations use `RECIPIENT_PUBLIC_URL`; staff notifications and account activation use `PUBLIC_URL`.

- Recipient endpoints are allowlisted under `/recipient-api/`. Staff endpoints remain under `/api/`. The recipient namespace has no account management, staff login, audit or setup routes.

- Staff and recipients use different session cookies. The recipient cookie is scoped to `/recipient-api/`; both cookies remain HTTP-only and become Secure under the protected deployment policy. Cookie domains remain host-only. CSRF is still enforced.

- Legacy `/api/recipient/*` routes are disabled by default and unavailable in production. Historical regression fixtures explicitly opt in through `ENABLE_LEGACY_RECIPIENT_API` in synthetic mode only. Existing invitation links redirect to the new recipient entry point.

- `@onesmarter.com` is an exact staff/admin email-domain restriction. Recipient mailboxes may use any valid email domain and require invitation-bound OTP verification.



`PUBLIC_URL` and `RECIPIENT_PUBLIC_URL` are public origins plus their entry paths, not email domains. Set recipient URLs with the `/recipient` path. Both virtual hosts must proxy the respective APIs to the application and serve the built frontend. Use host-only cookies; do not set a parent-domain session cookie. Separate DNS names alone do not enforce API isolation: the ingress must restrict the API namespace on each host if separate hosting is selected.



## Customer interface and operator tooling



The global development banner, test mailbox link and release-checklist panel have been removed from normal user pages. The test mailbox API and its hidden UI require `ENABLE_DEV_TOOLS=true` and remain restricted to loopback synthetic operation. Leave this setting false on shared deployments. Browser tests enable it only in their disposable environment. Production edge configuration explicitly denies web bootstrap and test-mailbox endpoints. Create the first administrator through `manage.py bootstrap_admin` after release approval.



A historical locally captured notification is labelled **Not emailed - local capture only**. It must never be relabelled as sent. Switching to SMTP will not resend previously captured messages automatically. Email requires sender credentials and authorized provider configuration; a localhost invitation cannot be opened by an external recipient on another computer.



## Release status: blocked



The clean interface is not production certification. `deploy/production.env.example` is a configuration handoff; production startup remains deliberately blocked. Do not use `APP_ENV=development` to bypass it on a public host.



Outstanding work includes independent hybrid-crypto review; approved PQ ingress/key/recovery coverage; custody and coordinated restore evidence; actual SMTP/delivery tests; immutable audit storage; region and backup/disposal policies; container resource/load verification. The selected instance-mounted persistent document storage also needs its production adapter/mount checks: the current local storage adapter is restricted to synthetic mode and the optional S3 adapter is not the selected document-storage target. See RELEASE_GATES.md and OPERATIONS_RUNBOOK.md.



The PQ ingress candidate uses separate virtual hosts: `staff.example.test` proxies only `/api/`, while `secure.example.test` proxies only `/recipient-api/`. Each rejects the other portal's API and UI entry paths; the staff host also rejects legacy `/api/recipient/` routes. The recipient root redirects to `/recipient/`. Unknown TLS names are rejected by the default server, and mismatched TLS SNI/HTTP host requests are rejected. Replace both example hostnames, including their SNI guards, and configure matching certificates and the origins in `deploy/pq.env.example`. The template still requires a compatible reviewed nginx/OpenSSL build, private socket permissions and deployment validation. No DNS, AWS resources, real email or public deployment was changed by this work.



## Trusted proxy and token buckets (29 October 2026)



The edge overwrites `X-Real-IP` with its socket peer and removes incoming

`X-Forwarded-For` / `Forwarded` assertions. Django trusts this single IP only

when the immediate peer is explicitly configured in `TRUSTED_PROXY_IPS` (exact

addresses; default empty). Missing/malformed assertions from a trusted peer

are rejected. Untrusted peers cannot override their socket address.



Compose sets `TRUSTED_PROXY_IPS=127.0.0.1`; nginx and Gunicorn share a network

namespace and Gunicorn binds only loopback. Do not publish the backend port.

For native Vite development, its proxy also overwrites these headers; set the

same variable on the API process. Loopback trust includes other local processes,

so use only on a trusted development machine. Never trust a broad Docker/private

subnet. A load balancer in front of nginx requires a separately reviewed real-IP

configuration; these templates assume nginx is the direct client-facing edge.



The PQ template uses `TRUSTED_PROXY_UNIX_SOCKET=true` only with Gunicorn bound

exclusively to the restricted Unix socket. Empty `REMOTE_ADDR` is trusted only

under this explicit option; it never grants trust to TCP peers. Socket ownership

must restrict writers to the gateway and application operators.



Each identified operation consumes tokens from both an identity-wide bucket and

an identity-plus-client-IP bucket. This preserves protection against source-IP

rotation without giving all accounts behind NAT one small allowance. Anonymous

landing/bootstrap requests use a client-IP bucket. Shared public-IP users still

share anonymous limits; distributed attacks and aggregate traffic need separate

edge capacity controls. An attacker can exhaust a targeted identity allowance;

this is the intentional account brute-force limit, not an organization-wide lock.



Existing `maximum` is bucket capacity; `seconds` is time to refill a completely

empty bucket. Login holds 10 tokens and refills one per 6 seconds; MFA holds 5

and refills one per 60 seconds. Integer credits preserve fractional refill,

cap at capacity, and are updated under database row locks. Exhaustion returns

429 without restarting a fixed window. A request denied by one applicable bucket

still counts as an attempt in the other. Backwards clock movement cannot mint

extra tokens; synchronized host clocks remain operationally necessary.



Migration `0006_token_rate_buckets` replaces transient fixed-window counters.

Stop old application/worker processes, apply `python manage.py migrate`, and

restart with matching code/configuration. This rollout resets rate allowances;

no accounts, conversations or documents are removed. Do not run mixed old/new

application versions against the changed rate-bucket schema.



### CI image and ingress gates



The browser job now runs `python scripts/check_compose_browser.py`. It builds the

root backend, PQ backend candidate and frontend images, runs `nginx -t` on both

the built default configuration and the **unchanged** `deploy/pq-nginx.conf` with

an ephemeral certificate, and runs Playwright through built nginx on port 8080.

`deploy/compose.ci.yaml` supplies disposable PostgreSQL, Redis, Celery worker/beat

and a real mTLS status fixture. Browser crypto/scanning remain explicitly synthetic;

the separate PQ key-service and real ClamAV jobs cover those boundaries. No SMTP

credentials are supplied, and all mail is captured inside the disposable stack.

The runner removes its Compose project and volumes on exit. Its ignored local

logs/session artifacts are not uploaded as public CI artifacts.



Actions are pinned to resolved upstream commit SHAs. Python audits cover both

lock files with pinned `pip-audit --strict`; npm audits include development tools.

The nginx base is digest-pinned to a current stable Alpine build for PQ config

support. Python 3.12 remains the ordinary backend target and 3.15 the PQ candidate;

both builds are required. The new container gates still need execution on a

Docker-capable runner; Docker is unavailable on the current Windows host.



Run locally on a Docker-capable machine after installing the locked Python and

frontend dependencies and Playwright Chromium:



```sh

python scripts/check_compose_browser.py

```



## Local evidence preservation and OTP sender update — 31 October 2026



See [EVIDENCE_ARCHIVE.md](EVIDENCE_ARCHIVE.md) for the implemented capture catalog, original-file hashes, server-download provenance, encrypted create-only local bundles, verified exports, legacy backfill and optional RFC 3161 verification. The user selected local preservation for now and an unset TSA. Deployment must not silently switch to AWS. Local preservation is not administrator-proof cloud WORM; pending timestamps are not trusted timestamps. Hospital-list reconciliation is excluded.



Emailed recipient OTP challenges authenticate through the organisation SMTP transport using the conversation owner's encrypted staff SMTP username and password. Only the From/envelope sender is support@onesmarter.com; Reply-To remains the staff address. No separate support password is required. The provider must authorize each staff account to send as support@onesmarter.com; rejected delivery fails closed without a sender fallback. Missing staff credentials block OTP delivery. Staff authenticator TOTP is unchanged. Ordinary conversation notifications retain each owning staff member's SMTP sender.



Local key-service calls now prefer the IPv4 loopback listener while retaining localhost certificate verification and PQ requirements. Every wrap/unwrap still contacts the service; no plaintext, data keys or readiness result is cached to achieve the speedup. Initial workspace session checks time out after eight seconds with retry; authenticated drafts survive transient polling failures.


## Plaintext upload buffering — 2026-10-31

The WSGI application uses only `BoundedMemoryUploadHandler`, a bounded Django memory upload handler. There is no TemporaryFileUploadHandler fallback. File payloads are capped at 25 MiB across a request; declared requests above 27 MiB are rejected, and DATA_UPLOAD_MAX_MEMORY_SIZE remains 27 MiB for non-file data. Actual file chunks are counted before buffering, including absent or understated lengths. Uploaded plaintext remains in RAM during validation, ClamAV INSTREAM scanning and encryption. Private object storage receives ciphertext.

Both nginx profiles disable request/response proxy buffering, explicitly use HTTP/1.1 upstream for chunked requests, and forbid proxy response temp files. The nginx main config's generic temp paths are not used for these streaming API locations. Do not enable body-capturing modules or buffered proxy overrides. This configuration is for WSGI; an ASGI server can spool a request before upload handlers run and requires a separate review.

Memory-only upload handling is not protection against host swap, hibernation, memory snapshots or crash dumps. Production hosts must disable or encrypt swap and disable core/crash dumps; exclude sensitive host memory snapshots from ordinary backups. Size worker concurrency and memory budgets for multiple copies of a 25 MiB upload during scanning/encryption. Preserve edge request limits. ClamAV's own extraction/temp-directory custody requires separate host verification. Existing historical temporary files are not retroactively removed by this change.

Regression coverage: staff and recipient multipart uploads over 1 MiB never invoke the disk handler and leave the configured temporary directory empty during scanning and after response; oversized/aggregate payloads are rejected. Nginx runtime verification requires the built deployment environment.

