"""Real TLS routing tests; PQ negotiation remains covered by the PQ CI job."""

import http.client
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


def test_shared_api_requires_client_certificate_only_for_integration(tmp_path):
    nginx = shutil.which("nginx")
    openssl = shutil.which("openssl")
    if not nginx or not openssl:
        if os.environ.get("REQUIRE_NGINX_TEST") == "1":
            pytest.fail("nginx and openssl are required")
        pytest.skip("nginx/openssl unavailable")

    def run(*args):
        subprocess.run([openssl, *args], cwd=tmp_path, check=True, capture_output=True)

    run(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=Test CA",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    )
    for name, usage in (("server", "serverAuth"), ("client", "clientAuth")):
        run(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            f"{name}.key",
            "-out",
            f"{name}.csr",
        )
        (tmp_path / f"{name}.ext").write_text(
            f"subjectAltName=DNS:localhost\nextendedKeyUsage={usage}\n"
        )
        run(
            "x509",
            "-req",
            "-in",
            f"{name}.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-out",
            f"{name}.pem",
            "-extfile",
            f"{name}.ext",
        )
    run(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=Untrusted client",
        "-keyout",
        "untrusted.key",
        "-out",
        "untrusted.pem",
    )
    requests = []

    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self):
            self.read_request()

        def do_POST(self):
            self.read_request()

        def read_request(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append((self.path, self.headers.get("Cookie")))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    source = Path(__file__).resolve().parents[2] / "deploy/aws-api.nginx.conf.example"
    server = source.read_text().replace("listen 443 ssl;", f"listen {port} ssl;")
    server = server.replace("securemailbackend.onesmarter.com", "localhost")
    for original, local in (
        ("api-fullchain.pem", "server.pem"),
        ("api.key", "server.key"),
        ("selfpay-client-ca.pem", "ca.pem"),
    ):
        server = server.replace(f"/etc/onesmarter/pki/{original}", str(tmp_path / local))
    # Stock Ubuntu nginx tests client-certificate routing, NOT PQ support.
    server = server.replace("X25519MLKEM768", "X25519")
    server = server.replace(
        "http://unix:/run/onesmarter/app.sock:",
        f"http://127.0.0.1:{upstream.server_port}",
    )
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
                pytest.fail("nginx start failed: " + (tmp_path / "error.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("nginx did not become ready")

        def request(path, identity=None, method="POST", body=b"{}"):
            context = ssl.create_default_context(cafile=str(tmp_path / "ca.pem"))
            if identity:
                context.load_cert_chain(
                    str(tmp_path / f"{identity}.pem"), str(tmp_path / f"{identity}.key")
                )
            connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=5)
            try:
                connection.request(
                    method,
                    path,
                    body,
                    {
                        "Cookie": "sessionid=test",
                        "X-SSL-Client-Verify": "SUCCESS",
                    },
                )
                response = connection.getresponse()
                response.read()
                return response.status
            finally:
                connection.close()

        path = "/api/integrations/threads"
        assert request("/api/auth/session", method="GET") == 204
        assert requests[-1] == ("/api/auth/session", "sessionid=test")
        assert request(path) == 403  # A forged HTTP header cannot replace mTLS.
        assert len(requests) == 1
        assert request(path, "client") == 204
        assert requests[-1] == (path, None)
        assert request(path, "client", method="GET") == 403
        assert request(path + "?unsigned=1", "client") == 400
        assert request(path, "client", body=b"x" * 32769) == 413
        try:
            assert request(path, "untrusted") in (400, 403)
        except ssl.SSLError:
            pass  # TLS rejection is also a fail-closed outcome.
        assert len(requests) == 2
    finally:
        process.terminate()
        process.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)
