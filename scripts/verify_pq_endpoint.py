"""Check an approved endpoint: hybrid succeeds, classical-only TLS must fail."""

import argparse
import json
import socket
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.transport import tls  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key):
        parser.error("Supply both client certificate and key.")
    context = tls.configure(ssl.create_default_context(cafile=args.ca), required=True)
    if args.cert:
        context.load_cert_chain(args.cert, args.key)
    with socket.create_connection((args.host, args.port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=args.host) as peer:
            tls.verify(peer, required=True)
    context.set_groups("X25519")
    # A TCP outage does not count as successful downgrade rejection.
    with socket.create_connection((args.host, args.port), timeout=10) as raw:
        try:
            with context.wrap_socket(raw, server_hostname=args.host):
                raise RuntimeError("Classical-only TLS was accepted; PQ policy is not enforced.")
        except ssl.SSLError as exc:
            if "ALERT_HANDSHAKE_FAILURE" not in str(exc):
                raise
    print(
        json.dumps(
            {"host": args.host, "port": args.port, "group": tls.GROUP, "classical_rejected": True}
        )
    )


if __name__ == "__main__":
    main()
