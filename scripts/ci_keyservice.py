"""CI-only status fixture: real mTLS, ephemeral custody, no published service port.

The built-stack browser drill uses synthetic local encryption.
Real PQ custody and real ClamAV have independent required integration jobs.
"""

import hashlib
import json
import os
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from backend.keyservice.server import Server, Service, tls_context
from backend.keyservice.store import KeyStore


def main():
    if os.environ.get("APP_ENV") != "test" or os.environ.get("CI") != "true":
        raise SystemExit("This fixture is restricted to disposable CI environments")
    directory = Path(os.environ.get("APP_RUNTIME_DIR", "/app/.runtime")) / "ci-status"
    directory.mkdir(mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CI status only")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), True
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("keyservice"), x509.DNSName("localhost")]),
            False,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    (directory / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (directory / "key.pem").chmod(0o600)
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    policy = directory / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "identities": {
                    fp: {
                        "name": "ci-status",
                        "role": "workload",
                        "organizations": [],
                        "operations": ["status"],
                        "expires_at": time.time() + 86400,
                    }
                }
            }
        )
    )
    secret = secrets.token_bytes(32)
    path = directory / "store.sqlite3"
    KeyStore.initialize(path, secret)
    store = KeyStore(path, directory / "backups")
    store.unseal(secret, "ci-bootstrap")
    service = Service(store, policy, "https://ci.example.test")
    with Server(
        ("0.0.0.0", int(os.environ.get("CI_STATUS_PORT", "8443"))),
        service,
        tls_context(
            str(directory / "cert.pem"), str(directory / "key.pem"), str(directory / "cert.pem")
        ),
        require_pq=False,
    ) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
