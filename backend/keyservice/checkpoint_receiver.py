"""Synthetic candidate checkpoint receiver; deploy under separate administration.

No enrollment, overwrite or deletion HTTP APIs. Enrollment is an offline
custodian action. PQ mTLS and a certificate fingerprint allowlist are mandatory.
"""

import argparse
import hashlib
import logging
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from backend.transport import tls

from . import protocol as p
from .checkpoints import CheckpointLog, packet_hash, require_candidate

logger = logging.getLogger(__name__)


class Receiver(HTTPServer):
    def __init__(self, address, log: CheckpointLog, policy: Path, context: ssl.SSLContext):
        self.log, self.policy, self.context = log, policy, context
        super().__init__(address, Handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        try:
            connection = self.context.wrap_socket(connection, server_side=True)
            tls.verify(connection, required=True)
            return connection, address
        except BaseException:
            connection.close()
            raise


class Handler(BaseHTTPRequestHandler):
    server_version = "CandidateCheckpointReceiver"
    sys_version = ""

    def log_message(self, *args):
        pass

    def respond(self, code: int, value: dict):
        payload = p.canonical(value)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def handle_checkpoint(self, write: bool):
        try:
            require_candidate()
            tls.verify(self.connection, required=True)
            fingerprint = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
            policy = p.parse_object(self.server.policy.read_bytes())
            identity = policy.get("identities", {}).get(fingerprint)
            prefix = "/v1/checkpoints/"
            if not identity or not self.path.startswith(prefix):
                raise PermissionError("Denied")
            store_id = self.path[len(prefix) :]
            if store_id not in identity.get("stores", []) or (
                write and identity.get("publish") is not True
            ):
                raise PermissionError("Denied")
            if self.headers.get("Transfer-Encoding") is not None:
                raise ValueError("Transfer encoding not accepted")
            lengths = self.headers.get_all("Content-Length", [])
            if write:
                if (
                    len(lengths) != 1
                    or not lengths[0].isdigit()
                    or not 0 < int(lengths[0]) <= 16384
                ):
                    raise ValueError("Invalid content length")
                size = int(lengths[0])
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError("Incomplete checkpoint")
                packet = p.parse_object(raw)
                self.server.log.accept(store_id, packet)
                self.respond(200, {"accepted_sha256": packet_hash(packet)})
            else:
                if lengths and lengths != ["0"]:
                    raise ValueError("GET body not accepted")
                self.respond(200, self.server.log.latest(store_id))
        except PermissionError:
            self.respond(403, {"error": "denied"})
        except (ValueError, KeyError, TypeError, InvalidSignature):
            self.respond(400, {"error": "invalid_checkpoint"})
        except Exception:
            logger.error("candidate_checkpoint_receiver_failure")
            self.respond(503, {"error": "unavailable"})

    def do_GET(self):
        self.handle_checkpoint(False)

    def do_PUT(self):
        self.handle_checkpoint(True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--log", type=Path, required=True)
    enroll = commands.add_parser("enroll")
    enroll.add_argument("--log", type=Path, required=True)
    enroll.add_argument("--enrollment", type=Path, required=True)
    serve = commands.add_parser("serve")
    for name in ("log", "policy", "cert", "key", "ca"):
        serve.add_argument("--" + name, type=Path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=9444)
    args = parser.parse_args()
    require_candidate()
    print(
        "WARNING: Unapproved synthetic checkpoint receiver; separate custody is required.",
        flush=True,
    )
    if args.command == "init":
        CheckpointLog.initialize(args.log)
    elif args.command == "enroll":
        value = p.parse_object(args.enrollment.read_bytes())
        CheckpointLog(args.log).enroll(value["public"], value["genesis"])
    else:
        context = tls.configure(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), required=True)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(args.ca))
        context.load_cert_chain(str(args.cert), str(args.key))
        with Receiver(
            (args.host, args.port), CheckpointLog(args.log), args.policy, context
        ) as server:
            server.serve_forever()


if __name__ == "__main__":
    main()
