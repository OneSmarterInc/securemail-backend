"""Add a status-only identity to the existing synthetic maintenance service."""

import hashlib
import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def main():
    directory = Path(__file__).resolve().parents[1] / ".runtime/maintenance"
    if (directory / "readiness.key").exists():
        raise SystemExit("Existing readiness identity preserved.")
    policy = json.loads((directory / "policy.json").read_text())
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic readiness only")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), True
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    (directory / "readiness.pem").write_bytes(pem)
    (directory / "readiness.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (directory / "client-ca.pem").write_bytes((directory / "ca.pem").read_bytes() + pem)
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    policy["identities"][fp] = {
        "name": "readiness",
        "role": "workload",
        "operations": ["status"],
        "organizations": [],
        "expires_at": time.time() + 90 * 86400,
    }
    (directory / "policy.json").write_text(json.dumps(policy, indent=2))
    for name in ("readiness.pem", "readiness.key", "client-ca.pem"):
        path = directory / name
        if os.name == "nt":
            account = subprocess.check_output(["whoami"], text=True).strip()
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", account + ":F", "/Q"],
                check=True,
                capture_output=True,
            )
        else:
            path.chmod(0o600)
    print("Status-only identity created. Restart the local service to load its client CA.")


if __name__ == "__main__":
    main()
