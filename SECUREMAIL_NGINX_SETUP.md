# Secure Mail site on the existing shared nginx

Domain: https://securemailbackend.onesmarter.com
API service name: securemailservice.service (alias of onesmarter-api.service).
This is the same Gunicorn process, ubuntu identity and /run/onesmarter/app.sock.
Do not create a second process or a second nginx listener on shared port 443.

## Install the API service alias

After updating the backend release at /var/www/securemail-backend/current:

```bash
cd /var/www/securemail-backend/current
sudo install -m 0644 deploy/onesmarter-api.service /etc/systemd/system/onesmarter-api.service
sudo systemctl daemon-reload
sudo systemctl enable onesmarter-api.service
systemctl show securemailservice.service --property=Id,Names,User
```

Enable creates the alias and target dependency; it does not start the process.
Keep onesmarter.target as the one-command startup for all application services.
The alias does not replace the separately sealed key service or its custodian.
Existing systemd drop-ins still apply; inspect them before changing a live service.

## Configure socket access without giving nginx the application group

```bash
getent group onesmarter-web || sudo groupadd --system onesmarter-web
sudo usermod -aG onesmarter-web www-data
sudo install -d -m 0755 /etc/systemd/system/onesmarter-api.service.d
sudo tee /etc/systemd/system/onesmarter-api.service.d/20-socket-group.conf >/dev/null <<'EOF'
[Service]
Group=onesmarter-web
SupplementaryGroups=ubuntu
EOF
sudo systemctl daemon-reload
```

The API still runs as ubuntu. The dedicated group grants socket access without
adding www-data to ubuntu or exposing backend.env to the web worker. Worker group
membership takes effect when nginx workers are replaced during the planned switch.

## Public HTTPS certificate

Confirm the domain points to this EC2 and obtain a public certificate. The private
key-service CA is not browser trusted. Inspect existing certificates first:

```bash
sudo certbot certificates
```

If this domain has no certificate, DNS challenge issuance avoids altering the live
sites or competing for port 80. Run the following and follow the DNS TXT prompts:

```bash
sudo certbot certonly --manual --preferred-challenges dns -d securemailbackend.onesmarter.com
```

Manual DNS issuance is not automatically renewable. Arrange DNS-plugin renewal
and reload operations before expiry. Use the actual lineage reported by Certbot;
the template assumes /etc/letsencrypt/live/securemailbackend.onesmarter.com/.

## Stage the site; do not enable on the old nginx

First check whether this file already exists. Preserve any existing configuration
rather than overwrite it. For a new site:

```bash
cd /var/www/securemail-backend/current
test ! -e /etc/nginx/sites-available/securemailbackend.onesmarter.com && sudo install -m 0644 deploy/securemailbackend.nginx.conf /etc/nginx/sites-available/securemailbackend.onesmarter.com
```

The site requires the new nginx linked against OpenSSL 3.5.9 and enforces hybrid
X25519MLKEM768 TLS. Do not symlink into sites-enabled while nginx.service still uses
the old /usr/sbin/nginx with OpenSSL 3.0.13: reload/renewal would then fail.
Do not install a competing nginx service on port 443.

Before switching the shared nginx executable, inspect its actual service:

```bash
sudo systemctl cat nginx.service
sudo /var/www/onesmarter-nginx/sbin/nginx -t -p /usr/share/nginx/ -c /etc/nginx/nginx.conf
```

Prepare an ExecStart/ExecStartPre/ExecReload override preserving the existing
PIDFile, flags and configuration prefix, plus rollback, from that actual unit.
The site must also pass a candidate-configuration nginx -t before activation.
A successful test of the old config alone does not validate this new TLS site.
The final switch affects all hosted sites and needs their HTTP/TLS smoke checks.
No live nginx service or DNS record has been changed by creating these files.

## Route boundaries

/api/ and /recipient-api/ proxy to the restricted Gunicorn Unix socket.
User-supplied client-IP forwarding headers are replaced, not trusted.
No response or request-body buffering is enabled for these routes.
SelfPay's integration endpoint is denied until its dedicated mTLS setup is ready.
/maintenance and /maintenance/ remain denied until a separate restricted gateway
with its own client certificate is configured. Raw key-service endpoints are never
publicly proxied. TLS identity/PQ transport and custodian unseal remain mandatory.

This site is for the API; the React frontend remains on Vercel. Database activity
logs remain in PostgreSQL, with no external audit archive.
