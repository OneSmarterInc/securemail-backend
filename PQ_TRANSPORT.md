# Post-quantum transport implementation


> Scope update — 2026-11-04: the owner removed antivirus from the product. Uploads undergo file-type/size validation, authorization, encryption and integrity checks; no malware verdict is produced. Historical scanning results below do not describe current functionality. Other release gates remain.


Updated 2026-10-28. Implemented and locally tested candidate; **production remains blocked**. Stored-file cryptography is unchanged. No real certificates, confidential files or recovery secrets were transmitted during development.



## Profile and runtime



The controlled staff-content, key-service, remote scanner and recovery-transfer candidate links listed below require TLS 1.3 with **X25519MLKEM768**, hostname/CA verification and, for internal services, dedicated client certificates. The shared Python adapter checks the actually negotiated group before sending application data. Session resumption is rejected; session tickets are disabled. Classical-only negotiation fails on internal hops. The public recipient edge prefers hybrid but accepts X25519 (QA-07); that fallback is not PQ protected. Staff classical connections receive only an upgrade notice, never protected content.



This profile uses the public Python 3.15 `SSLContext.set_groups()` and `SSLSocket.group()` APIs with hybrid-capable OpenSSL (3.5 or later). The existing Python 3.12/OpenSSL 3.0 development runtime cannot meet this requirement. Strict mode refuses it. The ignored portable Python used for local verification is a test tool, not a deployed runtime. Candidate container definition: `deploy/Dockerfile.pq`; build, pin/attest its resulting image, and verify compatibility on the target Linux host before release.



Sources: [Python SSL APIs](https://docs.python.org/3.15/library/ssl.html#ssl.SSLContext.set_groups), [OpenSSL supported groups](https://docs.openssl.org/master/man3/SSL_CTX_set1_groups_list/), [standard TLS hybrid exchange](https://www.rfc-editor.org/info/rfc10024/), [NGINX TLS configuration](https://nginx.org/en/docs/http/ngx_http_ssl_module.html).



PQ key exchange addresses connection confidentiality, including recorded-traffic risk. Existing certificate signatures are classical; this does not claim post-quantum authentication against an active quantum attacker. That threat model and authentication transition remain separately reviewed requirements.



## Scope exclusions



PostgreSQL, Redis and SMTP are **not verified post-quantum channels**. Ordinary TLS/STARTTLS on those connections does not make them post-quantum. These systems can carry session data, credentials, OTPs or ordinary-mail plaintext. No claim of complete key-bearing-hop PQ coverage is made. Production remains blocked until the threat model explicitly approves these exclusions or the required paths receive verified hybrid transport. Provider email delivery beyond our SMTP hop is also outside this claim.



## Connection paths



| Path | Implemented boundary | Deployment action still needed |

| --- | --- | --- |

| Browser to HTTPS edge | `deploy/pq-nginx.conf`: TLS 1.3; recipient hybrid preference with X25519 fallback and group telemetry; staff content requires hybrid; no resumption or early data | Install trusted hostname certificate; measure real browser/proxy support during pilot |

| Edge to Django | Permission-controlled Unix socket; no plaintext TCP backend | Run candidate Gunicorn Unix bind; share the socket only with the gateway, not untrusted containers |

| Django/workers to key service | `PQ_TRANSPORT_REQUIRED=true` uses strict mTLS and checks the group before HTTP request data | Set the workload PKI paths and deploy the upgraded runtime |

| Custodian browser to key service | Key-service CLI defaults to PQ-required; existing mTLS, password, CSRF and origin checks stay | Trusted dedicated maintenance hostname and custodian certificates; no TLS-terminating intermediary that changes peer identity |

| App to remote scanner gateway | Strict mTLS before INSTREAM bytes | Deploy gateway with a scanner-specific client CA and client identity |

| Backup transfer | `backend.transport.recovery`: verified PQ/mTLS PUT of an already encrypted snapshot, no redirects | Select receiver and authorization/retention; verify stored digest, replay behavior and actual restore |



Local Unix sockets/loopback are controlled host boundaries, not PQ-encrypted channels. Do not extend them to another machine or an untrusted shared network namespace. A root/host compromise is outside transport encryption's protection.



## Enabling the candidate



1. Keep `APP_ENV=test` for synthetic deployment validation. Do not remove the existing production gate. Review `deploy/pq.env.example`; provision real paths/hostnames outside source control. No credentials are included.

2. Run Django and Celery on the upgraded runtime with `PQ_TRANSPORT_REQUIRED=true`, the isolated key protector, and real ClamAV scanning. Plain TCP scanning is rejected. Secure session/CSRF cookies are enabled; the trusted HTTPS proxy indication is safe only when the backend is reachable exclusively through its protected Unix socket.

3. Replace the synthetic HTTP frontend listener with `deploy/pq-nginx.conf`; do not expose both listeners. Replace `staff.example.test` and `secure.example.test` in both server names and SNI guards, provision certificates covering those names, and match `PUBLIC_URL`, `RECIPIENT_PUBLIC_URL`, allowed hosts and CSRF origins in `deploy/pq.env.example`. Staff proxies only `/api/`; recipients proxy only `/recipient-api/`. Unknown hosts and SNI/Host mismatches are rejected. Run `nginx -t` with the actual certificate mounts. Use a build supporting OpenSSL 3.5 hybrid groups and the NGINX `$ssl_curve` variable. Unknown groups/configuration must stop startup. The existing synthetic Compose files are not a PQ deployment and are intentionally unchanged.

4. Start the key service using the documented `serve --synthetic-only` command on the upgraded runtime. PQ is required by default. `--allow-classical-synthetic` is a development-only escape hatch, never allowed in the strict profile. Existing Python 3.12 local previews need that explicit flag.

5. For remote scanning, configure clamd with `deploy/clamd-local.conf` and start:



The Unix-socket profile uses the same encrypted-file alerts and scan/resource limits as `deploy/clamd.conf`. Encrypted files and files that exceed scanning limits must be rejected, not reported clean. Run clamd as `clamav`; grant the gateway access to the socket's group and ensure `/run/clamav` and the signature database have appropriate ownership. Keep socket mode `660`. Restart clamd after configuration changes; validate encrypted and expanded-size-limit fixtures against the deployed daemon before sign-off.



```bash

python -m backend.transport.scanner --host 0.0.0.0 --port 3311 --cert /run/pki/scanner.pem --key /run/pki/scanner.key --ca /run/pki/scanner-client-ca.pem --socket /run/clamav/clamd.sock

```



For a same-namespace loopback backend, replace `--socket` with `--local-port 3310` and configure clamd to listen **only** on `127.0.0.1`. The gateway restricts accepted commands to INSTREAM and VERSION, 25 MiB total, 64 KiB chunks, authenticated TLS and at most 16 concurrent handlers. Protect the network perimeter and retain capacity/availability monitoring.



6. For a completed encrypted backup snapshot and an approved PUT receiver:



```bash

python -m backend.transport.recovery --encrypted-backup /backups/completed-snapshot.bin --url https://backup.example.test/approved-object --ca /run/pki/backup-ca.pem --cert /run/pki/recovery-client.pem --key /run/pki/recovery-client.key

```



The adapter does not encrypt a plaintext backup, invent retention policy, validate backup completeness or replace restore testing. Never transfer an unseal secret alongside its protected key-store snapshot. A receiver acceptance response is not evidence of durable archival; verify destination digest and restore separately. No automatic retries follow an uncertain PUT result.



## Verification and evidence



Run on the upgraded runtime:



```bash

python scripts/check_pq_transport.py

RUN_PQ_TRANSPORT=1 pytest backend/tests/test_keyservice.py backend/tests/test_pq_transport.py -q

```



On a machine with the project Playwright dependency and Edge installed, add `--browser` to the first command. `E2E_BROWSER=chromium` selects an installed Playwright Chromium instead. The browser test accepts an ephemeral test CA within its isolated context; real certificate/hostname rejection is independently exercised by TLS negative tests. It does not establish trust of a production certificate.



Local Python 3.15/OpenSSL 3.5.9 verification: **nine checks passed**, comprising hybrid success; classical client/server rejection; incorrect hostname, untrusted CA and missing client-certificate rejection; recovery-adapter transfer; scanner-gateway forwarding; and a headless Edge request whose group was verified on the server. The scanner backend is a synthetic protocol fixture, not an antivirus daemon. The CI job `pq-transport` fails rather than skips if required runtime support is missing; it has not yet run remotely.



Full repository test run on that isolated runtime with `RUN_PQ_TRANSPORT=1` and `RUN_KEY_PORTAL_BROWSER=1`: **120 passed, 11 skipped** in 92.68 seconds. This includes the actual key-service/Django integration and custodian browser unseal workflow with PQ-only service enforcement. Skipped environment-dependent tests are not deployment evidence. The older development runtime also passed its regression run (108 passed, 10 skipped at that point); it remains unsuitable for strict PQ mode. Test CA/leaf certificates were updated to satisfy newer strict certificate validation; validation was not relaxed.



Probe each actual network endpoint after deployment:



```bash

python scripts/verify_pq_endpoint.py --host portal.example.test --ca /run/pki/portal-ca.pem

python scripts/verify_pq_endpoint.py --host keys.example.test --port 8443 --ca /run/pki/keys-ca.pem --cert /run/pki/workload.pem --key /run/pki/workload.key

```



Repeat for scanner and backup endpoints with their dedicated client credentials. The probe sends no application data: it requires a verified hybrid handshake and a handshake-failure alert for a classical-only attempt. A connection timeout/outage is not counted as downgrade rejection. Repeat through any load balancer or ingress; checking a backend alone is insufficient.



## Still required before release



- Actual edge configuration test, production certificates, compatible visitor/staff browsers, and no reachable HTTP or raw scanner bypass.

- Network/identity isolation and the reviewed runtime/container dependency provenance on the selected host.

- Actual ClamAV clean/EICAR and outage behavior through its protected channel, not just the protocol fixture.

- Selected backup receiver, protected recovery workflow, off-instance storage, integrity/durability evidence and restore drill.

- Inventory any additional plaintext/credential-bearing paths, including database/Redis, SMTP, ingress and operator tools. Ordinary external email is not covered by this PQ profile. Do not infer complete coverage from these tests.

- Independent hybrid/custody review and the remaining gates in `RELEASE_GATES.md`.

