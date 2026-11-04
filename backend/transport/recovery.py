"""Transfer an already-encrypted backup over verified hybrid mTLS; no redirects."""

import argparse
import http.client
from pathlib import Path
from urllib.parse import urlsplit

from . import tls


def checkpoint_request(
    method: str, url: str, ca: str, cert: str, key: str, payload: bytes | None = None
) -> bytes:
    """Bounded checkpoint GET/PUT with mandatory hybrid mTLS and no redirects."""
    target = urlsplit(url)
    if (
        method not in {"GET", "PUT"}
        or target.scheme != "https"
        or not target.hostname
        or target.username is not None
        or target.password is not None
        or target.fragment
        or target.query
        or (payload is not None and len(payload) > 16384)
    ):
        raise ValueError("Invalid checkpoint request")
    context = tls.client_context(ca, cert, key, required=True)
    conn = http.client.HTTPSConnection(target.hostname, target.port, context=context, timeout=10)
    try:
        conn.connect()
        tls.verify(conn.sock, required=True)
        conn.request(
            method,
            target.path or "/",
            body=payload,
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
            },
        )
        response = conn.getresponse()
        if response.status != 200:
            raise OSError("Checkpoint receiver did not confirm acceptance")
        raw = response.read(16385)
        if len(raw) > 16384:
            raise ValueError("Oversized checkpoint response")
        return raw
    finally:
        conn.close()


def upload_encrypted_backup(path: Path, url: str, ca: str, cert: str, key: str) -> None:
    target = urlsplit(url)
    if (
        target.scheme != "https"
        or not target.hostname
        or target.username is not None
        or target.password is not None
        or target.fragment
    ):
        raise ValueError("Use an authenticated HTTPS backup destination without URL credentials.")
    context = tls.client_context(ca, cert, key, required=True)
    conn = http.client.HTTPSConnection(target.hostname, target.port, context=context, timeout=30)
    try:
        conn.connect()
        tls.verify(conn.sock, required=True)
        with path.open("rb") as source:
            # Open once; the operator must supply a completed, immutable backup snapshot.
            import os

            size = os.fstat(source.fileno()).st_size
            route = target.path or "/"
            if target.query:
                route += "?" + target.query
            conn.putrequest("PUT", route)
            conn.putheader("Content-Length", str(size))
            conn.putheader("Content-Type", "application/octet-stream")
            conn.endheaders()
            remaining = size
            while remaining:
                chunk = source.read(min(65536, remaining))
                if not chunk:
                    raise OSError("Backup changed during transfer")
                conn.send(chunk)
                remaining -= len(chunk)
            response = conn.getresponse()
            if response.status not in {200, 201, 204}:
                raise OSError(
                    "Backup destination did not confirm acceptance; verify before retrying"
                )
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--encrypted-backup", type=Path, required=True)
    for name in ("url", "ca", "cert", "key"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    upload_encrypted_backup(args.encrypted_backup, args.url, args.ca, args.cert, args.key)
    print("Destination accepted the transfer; verify its stored digest and restore separately.")


if __name__ == "__main__":
    main()
