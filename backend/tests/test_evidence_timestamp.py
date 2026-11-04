"""Real RFC 3161 signatures from a disposable local test authority, never a public TSA."""

import base64
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from backend.apps.core import evidence
from backend.tests.test_evidence import submitted

pytestmark = pytest.mark.django_db


@pytest.fixture
def local_tsa(settings, tmp_path):
    executable = shutil.which("openssl")
    if not executable:
        pytest.skip("OpenSSL CLI required for real RFC 3161 tests")
    settings.EVIDENCE_OPENSSL = executable
    now = datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable test TSA root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable timestamp signer")])
        )
        .issuer_name(root_name)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    (tmp_path / "root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "signer.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "signer.key").write_bytes(
        signer_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (tmp_path / "serial").write_text("01")
    configuration = tmp_path / "tsa.cnf"
    configuration.write_text(f"""[tsa]
default_tsa = signer
[signer]
serial = {tmp_path.as_posix()}/serial
signer_cert = {tmp_path.as_posix()}/signer.pem
certs = {tmp_path.as_posix()}/root.pem
signer_key = {tmp_path.as_posix()}/signer.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
""")
    settings.EVIDENCE_TSA_URL = "https://tsa.example.test/"
    settings.EVIDENCE_TSA_CA_FILE = str(tmp_path / "root.pem")

    def reply(url, *, limit, body):
        query, response = tmp_path / "request.tsq", tmp_path / "response.tsr"
        query.write_bytes(body)
        result = subprocess.run(
            [
                executable,
                "ts",
                "-reply",
                "-config",
                str(configuration),
                "-queryfile",
                str(query),
                "-out",
                str(response),
            ],
            capture_output=True,
            timeout=20,
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        return response.read_bytes(), url, "application/timestamp-reply"

    return reply


def test_real_timestamp_signature_nonce_and_digest_checks(
    staff_client, local_tsa, monkeypatch, settings, tmp_path
):
    row = submitted(staff_client)
    monkeypatch.setattr(evidence, "retrieve", local_tsa)
    evidence.timestamp_capture(row.evidence_capture_id)
    capture = row.evidence_capture
    capture.refresh_from_db()
    assert capture.timestamp_state == "verified"
    manifest, _ = evidence.read_bundle(capture)
    import json

    from backend.apps.core import crypto

    proof = json.loads(
        crypto.decrypt(
            evidence.path_for(capture, "timestamp").read_text(),
            evidence.context(capture, "evidence-timestamp"),
        )
    )
    evidence.verify_timestamp(manifest, proof)
    different_query = Path(settings.EVIDENCE_TSA_CA_FILE).parent / "different.tsq"
    evidence.openssl(
        "-query",
        "-sha256",
        "-digest",
        evidence.digest(evidence.canonical(manifest)),
        "-cert",
        "-out",
        different_query,
    )
    with pytest.raises(ValueError):
        evidence.verify_timestamp(
            manifest, {**proof, "query": base64.b64encode(different_query.read_bytes()).decode()}
        )
    with pytest.raises(ValueError):
        evidence.verify_timestamp({**manifest, "source_url": "https://forged.example/"}, proof)
    damaged = bytearray(base64.b64decode(proof["reply"]))
    damaged[-1] ^= 1
    with pytest.raises(ValueError):
        evidence.verify_timestamp(manifest, {**proof, "reply": base64.b64encode(damaged).decode()})
    assert staff_client.get(f"/api/evidence/{capture.pk}/export").status_code == 200
