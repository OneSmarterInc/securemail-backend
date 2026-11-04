"""Exercise the shipped nginx configuration against a disposable Django test server."""

import http.client
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
from django.utils import timezone


@pytest.mark.django_db(transaction=True)
def test_real_nginx_client_isolation(live_server, settings, tmp_path, monkeypatch):
    nginx = shutil.which("nginx")
    if not nginx:
        if os.environ.get("REQUIRE_NGINX_TEST") == "1":
            pytest.fail("nginx is required for the proxy regression job")
        pytest.skip("nginx executable unavailable")
    now = timezone.now()
    monkeypatch.setattr("backend.apps.core.services.timezone.now", lambda: now)
    settings.TRUSTED_PROXY_IPS = {"127.0.0.1"}
    settings.ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]
    monkeypatch.setattr("backend.apps.core.auth.authenticate", lambda *a, **kw: None)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    source = Path(__file__).resolve().parents[2] / "deploy" / "local-nginx.conf"
    server = source.read_text().replace("listen 8080;", f"listen 127.0.0.1:{port};")
    server = server.replace("http://127.0.0.1:8000", live_server.url)
    config = tmp_path / "nginx.conf"
    config.write_text(
        f"daemon off; master_process off; pid {tmp_path}/nginx.pid;\n"
        f"error_log {tmp_path}/error.log;\nevents {{}}\nhttp {{\n"
        f"client_body_temp_path {tmp_path}/body;\nproxy_temp_path {tmp_path}/proxy;\n"
        + server
        + "\n}\n"
    )
    process = subprocess.Popen(
        [nginx, "-p", str(tmp_path), "-c", str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if process.poll() is not None:
                pytest.fail("nginx failed to start: " + (tmp_path / "error.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("nginx did not become ready")

        def session(ip):
            conn = http.client.HTTPConnection("127.0.0.1", port, source_address=(ip, 0), timeout=5)
            conn.request("GET", "/api/auth/session")
            response = conn.getresponse()
            cookie = response.getheader("Set-Cookie").split(";", 1)[0]
            token = json.loads(response.read())["csrf"]
            conn.close()
            return cookie, token

        def post(ip, path, body, forged):
            cookie, token = session(ip)
            conn = http.client.HTTPConnection("127.0.0.1", port, source_address=(ip, 0), timeout=5)
            conn.request(
                "POST",
                path,
                json.dumps(body),
                {
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "X-CSRFToken": token,
                    "X-Real-IP": forged,
                    "X-Forwarded-For": forged,
                    "Forwarded": "for=" + forged,
                },
            )
            response = conn.getresponse()
            response.read()
            conn.close()
            return response.status

        for i in range(10):
            assert (
                post(
                    "127.0.0.2",
                    "/api/auth/login",
                    {
                        "email": "alice@onesmarter.com",
                        "password": "invalid-test-only",
                    },
                    f"198.51.100.{i + 1}",
                )
                == 401
            )
        assert (
            post(
                "127.0.0.2",
                "/api/auth/login",
                {
                    "email": "alice@onesmarter.com",
                    "password": "invalid-test-only",
                },
                "203.0.113.5",
            )
            == 429
        )
        assert (
            post(
                "127.0.0.2",
                "/api/auth/login",
                {
                    "email": "bob@onesmarter.com",
                    "password": "invalid-test-only",
                },
                "203.0.113.5",
            )
            == 401
        )
        for i in range(60):
            assert (
                post(
                    "127.0.0.2",
                    "/recipient-api/recipient/landing",
                    {"token": "synthetic-invalid-token"},
                    f"198.51.100.{i + 1}",
                )
                == 404
            )
        assert (
            post(
                "127.0.0.2",
                "/recipient-api/recipient/landing",
                {"token": "synthetic-invalid-token"},
                "203.0.113.5",
            )
            == 429
        )
        assert (
            post(
                "127.0.0.3",
                "/recipient-api/recipient/landing",
                {"token": "synthetic-invalid-token"},
                "203.0.113.5",
            )
            == 404
        )
    finally:
        process.terminate()
        process.wait(timeout=10)
