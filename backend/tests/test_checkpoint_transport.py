"""Recovery checkpoint transport policy plus opt-in actual PQ/mTLS receiver drill."""

import os
import ssl
import threading
from unittest.mock import Mock

import pytest

from backend.keyservice import protocol as p
from backend.keyservice.checkpoint_receiver import Receiver
from backend.keyservice.checkpoints import RemotePublisher
from backend.tests.test_candidate_audit import enroll
from backend.tests.test_keyservice import certificates
from backend.transport import recovery, tls


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/x",
        "https://u:p@localhost/x",
        "https://localhost/x#secret",
        "https://localhost/x?q=1",
    ],
)
def test_checkpoint_transport_rejects_unsafe_destinations(url, monkeypatch):
    connect = Mock()
    monkeypatch.setattr(recovery.http.client, "HTTPSConnection", connect)
    with pytest.raises(ValueError):
        recovery.checkpoint_request("GET", url, "ca", "cert", "key")
    connect.assert_not_called()


def test_checkpoint_never_sends_before_verified_pq_handshake(monkeypatch):
    context = Mock()
    monkeypatch.setattr(tls, "client_context", Mock(return_value=context))
    connection = Mock()
    monkeypatch.setattr(recovery.http.client, "HTTPSConnection", Mock(return_value=connection))
    monkeypatch.setattr(tls, "verify", Mock(side_effect=ssl.SSLError("classical peer")))
    with pytest.raises(ssl.SSLError):
        recovery.checkpoint_request("PUT", "https://localhost/x", "ca", "cert", "key", b"synthetic")
    connection.request.assert_not_called()
    connection.close.assert_called_once()
    tls.client_context.assert_called_once_with("ca", "cert", "key", required=True)


@pytest.mark.parametrize("status,size", [(302, 0), (500, 0), (200, 16385)])
def test_checkpoint_response_redirect_error_and_size_fail_closed(monkeypatch, status, size):
    monkeypatch.setattr(tls, "client_context", Mock())
    monkeypatch.setattr(tls, "verify", Mock())
    connection = Mock()
    connection.getresponse.return_value.status = status
    connection.getresponse.return_value.read.return_value = b"x" * size
    monkeypatch.setattr(recovery.http.client, "HTTPSConnection", Mock(return_value=connection))
    with pytest.raises((ValueError, OSError)):
        recovery.checkpoint_request("GET", "https://localhost/x", "ca", "cert", "key")
    assert connection.request.call_count == 1


@pytest.mark.skipif(
    os.environ.get("RUN_PQ_TRANSPORT") != "1",
    reason="Requires actual Python/OpenSSL hybrid TLS runtime",
)
def test_actual_pq_checkpoint_receiver_unseal_seal_and_denied_identity(tmp_path, monkeypatch):
    import secrets

    from backend.keyservice.candidate_audit import CandidateKeyStore

    monkeypatch.setenv("KEY_SERVICE_AUDIT_CANDIDATE", "true")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SYNTHETIC_MODE", "true")
    monkeypatch.delenv("KEY_SERVICE_CHECKPOINT_CONFIG", raising=False)
    secret = secrets.token_bytes(32)
    store = CandidateKeyStore.initialize(
        tmp_path / "store.db", secret, backup_directory=tmp_path / "backups"
    )
    local = enroll(store, tmp_path)
    certs = certificates(tmp_path)
    context = tls.configure(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), required=True)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(certs["ca"]))
    context.load_cert_chain(str(certs["server"][0]), str(certs["server"][1]))
    policy = tmp_path / "receiver-policy.json"
    policy.write_bytes(
        p.canonical(
            {"identities": {certs["workload"][2]: {"stores": [local.store_id], "publish": True}}}
        )
    )
    with Receiver(("127.0.0.1", 0), local.log, policy, context) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = tmp_path / "publisher.json"
            values = {
                "store_id": local.store_id,
                "public": local.public,
                "url": f"https://localhost:{server.server_port}/v1/checkpoints/{local.store_id}",
                "ca": str(certs["ca"]),
                "cert": str(certs["workload"][0]),
                "key": str(certs["workload"][1]),
            }
            config.write_bytes(p.canonical(values))
            store.publisher = RemotePublisher(config)
            store.unseal(secret, "custodian")
            store.seal("custodian")
            assert store.publisher.latest()["record"]["event"] == "seal"
            values["cert"], values["key"] = (
                str(certs["maintenance"][0]),
                str(certs["maintenance"][1]),
            )
            config.write_bytes(p.canonical(values))
            with pytest.raises(OSError, match="receiver"):
                RemotePublisher(config).latest()
        finally:
            server.shutdown()
            thread.join(timeout=10)
