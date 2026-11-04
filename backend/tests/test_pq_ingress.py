"""Host routing regression; TLS negotiation needs the deployed PQ-capable nginx."""

import http.client
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "deploy" / "pq-nginx.conf"


def test_pq_hosts_have_separate_upstreams_and_tls_guards():
    source = SOURCE.read_text()
    default, staff, recipient = source.split("server {\n")[1:]
    assert "ssl_reject_handshake on;" in default
    for block, host, namespace in (
        (staff, "staff.example.test", "/api/"),
        (recipient, "secure.example.test", "/recipient-api/"),
    ):
        assert f"server_name {host};" in block
        assert f'if ($ssl_server_name != "{host}") {{ return 421; }}' in block
        if block == staff:
            assert 'if ($ssl_curve != "X25519MLKEM768") { return 403; }' in block
        else:
            assert "ssl_ecdh_curve X25519MLKEM768:X25519;" in block
            assert "if ($ssl_curve" not in block
            assert "recipient_transport;" in block
        assert block.count("proxy_pass ") == 1
        assert re.search(r"location (?:\^~ )?" + namespace + r" \{\s+proxy_pass", block)
    assert "location ^~ /api/ { return 404; }" in recipient
    assert "location ^~ /recipient-api/ { return 404; }" in staff


def test_real_nginx_pq_host_routing(tmp_path):
    nginx = shutil.which("nginx")
    if not nginx:
        if os.environ.get("REQUIRE_NGINX_TEST") == "1":
            pytest.fail("nginx is required for the proxy regression job")
        pytest.skip("nginx executable unavailable")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    source = SOURCE.read_text()
    # Stock nginx lacks ssl_curve: stub telemetry only in this HTTP routing test.
    # Exercise the shipped routing on stock nginx over loopback HTTP. Only TLS
    # directives and the upstream are replaced; this is not a PQ/TLS test.
    source = re.sub(r"^    ssl_.*\n", "", source, flags=re.M)
    source = re.sub(r"^    if \(\$ssl_.*\n", "", source, flags=re.M)
    source = source.replace("$ssl_curve", "not-tested")
    source = source.replace("listen 443 ssl", f"listen 127.0.0.1:{port}")
    source = source.replace("proxy_pass http://unix:/run/onesmarter/app.sock:;", "return 204;")
    config = tmp_path / "nginx.conf"
    config.write_text(
        f"daemon off; master_process off; pid {tmp_path.as_posix()}/nginx.pid;\n"
        f"error_log {tmp_path.as_posix()}/error.log;\nevents {{}}\nhttp {{\n"
        f"access_log off;\nclient_body_temp_path {tmp_path.as_posix()}/body;\n"
        f"proxy_temp_path {tmp_path.as_posix()}/proxy;\n{source}\n}}\n"
    )
    process = subprocess.Popen(
        [nginx, "-p", str(tmp_path), "-c", str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(100):
            if process.poll() is not None:
                pytest.fail(
                    "nginx failed: "
                    + process.communicate()[1].decode()
                    + (tmp_path / "error.log").read_text()
                )
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("nginx did not start")
        for host, path, expected in (
            ("staff.example.test", "/api/auth/login", 204),
            ("staff.example.test", "/api/admin/accounts", 204),
            ("staff.example.test", "/recipient-api/auth/session", 404),
            ("staff.example.test", "/api/recipient/code", 404),
            ("staff.example.test", "/api/auth/setup", 404),
            ("staff.example.test", "/api/dev/inbox", 404),
            ("secure.example.test", "/recipient-api/auth/session", 204),
            ("secure.example.test", "/api/auth/login", 404),
            ("secure.example.test", "/api/admin/accounts", 404),
            ("secure.example.test", "/%61pi/auth/login", 404),
            ("secure.example.test", "/recipient-api/../api/auth/login", 404),
            ("secure.example.test", "/staff/", 404),
            ("secure.example.test", "/", 302),
        ):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.request("GET", path, headers={"Host": host})
                response = conn.getresponse()
                response.read()
                assert response.status == expected, (host, path)
            finally:
                conn.close()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", "/api/auth/login", headers={"Host": "unknown.example.test"})
            with pytest.raises(http.client.RemoteDisconnected):
                conn.getresponse()
        finally:
            conn.close()
    finally:
        process.terminate()
        process.wait(timeout=5)
