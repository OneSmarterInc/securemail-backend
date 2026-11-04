"""Real loopback hybrid handshakes; requires Python 3.15+ and OpenSSL CLI >=3.5.

Uses temporary synthetic certificates, never application secrets. Nonzero exit
means failure, including an unsupported runtime (never silently skip).
"""

import argparse
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.transport import tls  # noqa: E402
from backend.transport.recovery import upload_encrypted_backup  # noqa: E402


def adapters(context, client_context, directory, cert, key, browser=False):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_PUT(self):
            tls.verify(self.connection, required=True)
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(204)
            self.end_headers()

        def do_GET(self):
            tls.verify(self.connection, required=True)
            received.append("browser:" + self.connection.group())
            body = b"PQ verified"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)

    class HTTPS(ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            # Browsers may abandon speculative connections to this temporary server.
            pass

        def get_request(self):
            raw, address = super().get_request()
            raw.settimeout(10)
            try:
                return context.wrap_socket(raw, server_side=True), address
            except BaseException:
                raw.close()
                raise

    http = HTTPS(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=http.serve_forever)
    thread.start()
    origin = f"https://localhost:{http.server_port}"
    try:
        backup = Path(directory) / "synthetic-backup.bin"
        backup.write_bytes(b"Synthetic backup transfer fixture")
        upload_encrypted_backup(backup, origin + "/backup", str(cert), str(cert), str(key))
        if not (received == [backup.read_bytes()]):
            raise RuntimeError("Transport verification failed")
        if browser:
            result = subprocess.run(
                ["node", str(Path(__file__).with_name("check_pq_browser.mjs"))],
                input=json.dumps({"origin": origin, "cert": str(cert), "key": str(key)}),
                text=True,
                capture_output=True,
                timeout=45,
            )
            if not (result.returncode == 0):
                raise RuntimeError(result.stderr)
            if "browser:" + tls.GROUP not in received:
                raise RuntimeError("Transport verification failed")
    finally:
        http.shutdown()
        http.server_close()
        thread.join(10)


def exchange(server_context, client_context, *, hostname="localhost", success=True):
    results = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)

    def serve():
        try:
            raw, _ = listener.accept()
            raw.settimeout(5)
            with raw, server_context.wrap_socket(raw, server_side=True) as peer:
                results.append(peer.group())
                data = peer.recv(4)
                if data:
                    results.append("received_application_data")
                    peer.sendall(data)
        except (OSError, ValueError):
            pass

    thread = threading.Thread(target=serve)
    thread.start()
    accepted = False
    try:
        with socket.create_connection(listener.getsockname(), timeout=5) as raw:
            with client_context.wrap_socket(raw, server_hostname=hostname) as peer:
                if success:
                    tls.verify(peer, required=True)
                peer.sendall(b"test")
                accepted = peer.recv(4) == b"test"
    except (OSError, ValueError):
        pass
    finally:
        thread.join(12)
        listener.close()
    if thread.is_alive():
        raise RuntimeError("TLS worker did not terminate")
    if not (accepted == success):
        raise RuntimeError((success, accepted, results))
    if success:
        if not (results == [tls.GROUP, "received_application_data"]):
            raise RuntimeError(results)
    else:
        if "received_application_data" in results:
            raise RuntimeError(results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--temp-root", type=Path, default=Path(".runtime"))
    parser.add_argument("--browser", action="store_true")
    args = parser.parse_args()
    tls.configure(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), required=True)
    args.temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pq-tls-", dir=args.temp_root) as directory:
        cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        config = Path(directory) / "openssl.cnf"
        config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")
        subprocess.run(
            [
                args.openssl,
                "req",
                "-config",
                str(config),
                "-x509",
                "-newkey",
                "rsa:2048",
                "-noenc",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-addext",
                "extendedKeyUsage=serverAuth,clientAuth",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,digitalSignature,keyEncipherment",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )

        def server(classical=False):
            ctx = tls.configure(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), required=True)
            ctx.load_cert_chain(cert, key)
            ctx.load_verify_locations(cert)
            ctx.verify_mode = ssl.CERT_REQUIRED
            if classical:
                ctx.set_groups("X25519")
            return ctx

        def client(classical=False, certificate=True):
            ctx = tls.configure(ssl.create_default_context(cafile=str(cert)), required=True)
            if certificate:
                ctx.load_cert_chain(cert, key)
            if classical:
                ctx.set_groups("X25519")
            return ctx

        exchange(server(), client())
        exchange(server(), client(classical=True), success=False)
        exchange(server(classical=True), client(), success=False)
        exchange(server(), client(), hostname="wrong.example", success=False)
        exchange(server(), client(certificate=False), success=False)
        untrusted = tls.configure(ssl.create_default_context(), required=True)
        untrusted.load_cert_chain(cert, key)
        exchange(server(), untrusted, success=False)
        adapters(server(), client(), directory, cert, key, args.browser)
    print(
        json.dumps(
            {
                "passed": 8 if args.browser else 7,
                "group": tls.GROUP,
                "openssl": ssl.OPENSSL_VERSION,
                "scope": "real loopback TLS and recovery adapters; deployment unverified",
            }
        )
    )


if __name__ == "__main__":
    main()
