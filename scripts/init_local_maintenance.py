"""Provision synthetic localhost custody, never production identity or recovery material."""

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.keyservice import protocol  # noqa: E402
from backend.keyservice.custodian_accounts import CustodianAccounts  # noqa: E402
from backend.keyservice.store import KeyStore  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-local-recovery-synthetic", action="store_true", required=True)
    parser.parse_args()
    directory = ROOT / ".runtime/maintenance"
    custody = ROOT / ".runtime/maintenance-credentials"
    if directory.exists() or custody.exists():
        raise SystemExit("Existing setup preserved; inspect it instead of replacing keys.")
    directory.mkdir(mode=0o700)
    custody.mkdir(mode=0o700)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OneSmarter local test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(issuer)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), True
        )
        .sign(ca_key, hashes.SHA256())
    )
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    certificates = {}
    for name in ("server", "gateway"):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
            )
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, False, False, False, False), True
            )
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH
                        if name == "server"
                        else ExtendedKeyUsageOID.CLIENT_AUTH
                    ]
                ),
                False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        (directory / (name + ".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (directory / (name + ".key")).write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        certificates[name] = cert
    password = secrets.token_urlsafe(24)
    recovery = secrets.token_bytes(32)
    KeyStore.initialize(directory / "store.sqlite3", recovery)
    fingerprint = hashlib.sha256(
        certificates["gateway"].public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    policy = {
        "identities": {
            fingerprint: {
                "name": "custodian",
                "role": "custodian",
                "organizations": [],
                "operations": ["custody-status", "unseal", "seal", "rotate-root"],
                "expires_at": time.time() + 90 * 86400,
            }
        }
    }
    (directory / "policy.json").write_text(json.dumps(policy, indent=2), encoding="utf-8")
    CustodianAccounts(directory / "custodians").create("custodian", "Custodian", password)
    (custody / "custodian-password.txt").write_text(password, encoding="ascii")
    (custody / "unseal-key.txt").write_text(protocol.encode(recovery), encoding="ascii")
    for folder in (directory, custody):
        for path in folder.iterdir():
            if path.is_file():
                path.chmod(0o600)
    if os.name == "nt":
        account = subprocess.check_output(["whoami"], text=True).strip()
        for folder in (directory, custody):
            subprocess.run(
                ["icacls", str(folder), "/inheritance:r", "/grant:r", account + ":(OI)(CI)F", "/Q"],
                check=True,
                capture_output=True,
            )
            for path in folder.iterdir():
                if path.is_file():
                    subprocess.run(
                        ["icacls", str(path), "/inheritance:r", "/grant:r", account + ":F", "/Q"],
                        check=True,
                        capture_output=True,
                    )
    print("Synthetic maintenance initialized. Username: custodian. Secrets were not printed.")
    print("Move the initial password and recovery key into separate secure custody after setup.")


if __name__ == "__main__":
    main()
