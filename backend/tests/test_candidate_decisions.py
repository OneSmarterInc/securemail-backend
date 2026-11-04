"""Internal D1-D6 acceptance probes; synthetic fixtures, not external approval."""

import copy
import secrets
import sqlite3
import uuid
from contextlib import closing

import pytest

from backend.keyservice import protocol as p
from backend.keyservice.candidate_audit import CandidateKeyStore
from backend.keyservice.checkpoints import CheckpointLog, verify_packet
from backend.tests import test_keyservice
from backend.tests.test_candidate_audit import candidate_env as candidate_env
from backend.tests.test_candidate_audit import vault as vault
from backend.tests.test_keyservice import portal_request


@pytest.fixture
def live_service(vault, tmp_path, settings):
    yield from test_keyservice.live_service.__wrapped__(vault[:2], tmp_path, settings)


def test_override_is_explicit_and_export_restores_verified_status(vault, monkeypatch):
    from backend.apps.core import document_service

    store, secret, publisher, org, context, dek, wrapper = vault
    store.seal("custodian")
    publisher.down = True
    with pytest.raises(OSError):
        store.unseal(secret, "custodian")
    with pytest.raises(ValueError, match="20 to 500"):
        store.unseal(secret, "custodian", override_reason="short")
    store.unseal(
        secret, "custodian", override_reason="Receiver outage during authorized recovery drill"
    )
    assert store.audit_integrity == "unverified_override"
    assert store.unwrap(org, context, wrapper, "worker") == dek
    monkeypatch.setattr(document_service, "read_status", store.status)
    assert not document_service.ready()
    with closing(sqlite3.connect(store.path)) as db:
        rows = db.execute("SELECT body,mac FROM audit").fetchall()
    assert any(
        p.parse_object(body)["operation"] == "integrity_override" and mac for body, mac in rows
    )
    publisher.down = False
    store.last_export_time = 0
    store.next_export_retry = 0
    store.tick()
    assert not store.override_active and not store.export_pending
    assert document_service.ready()


def test_mutable_wrap_allowed_during_receiver_outage_but_rotation_refused(vault):
    store, _, publisher, org, *_ = vault
    version = store.list_versions(org)[0]["id"]
    context = f"secure-mail:v1:organization={org}:smtp-credential=staff"
    publisher.down = True
    first = secrets.token_bytes(32)
    store.wrap(org, context, first, version, "worker")
    second = secrets.token_bytes(32)
    wrapper = store.wrap(org, context, second, version, "worker")
    assert store.unwrap(org, context, wrapper, "worker") == second
    with pytest.raises(OSError):
        store.rotate(org, version, str(uuid.uuid4()), "maintenance")
    assert store.root is None


def test_restore_override_stays_sealed_and_seal_revokes_override(vault, tmp_path):
    store, secret, publisher, *_ = vault
    store.seal("custodian")
    source = tmp_path / "copy.db"
    store.backup(source)
    publisher.down = True
    with pytest.raises(OSError):
        CandidateKeyStore.restore(source, tmp_path / "refused.db", secret, publisher=publisher)
    restored = CandidateKeyStore.restore(
        source,
        tmp_path / "override.db",
        secret,
        publisher=publisher,
        override_reason="Authorized clean machine recovery during outage",
        actor="custodian",
    )
    assert restored.root is None and restored.audit_integrity == "unverified_override"
    store.unseal(
        secret, "custodian", override_reason="Authorized recovery while receiver is unavailable"
    )
    with pytest.raises(OSError):
        store.seal("custodian")
    assert store.root is None and not store.override_active
    with pytest.raises(OSError):
        store.unseal(secret, "custodian")


def test_override_cannot_bypass_corrupt_checkpoint(vault, monkeypatch):
    store, secret, publisher, *_ = vault
    store.seal("custodian")
    packet = copy.deepcopy(publisher.latest())
    packet["record"]["sig_alg"] = "unknown"
    monkeypatch.setattr(publisher, "latest", lambda: packet)
    with pytest.raises(ValueError):
        store.unseal(
            secret, "custodian", override_reason="Authorized recovery while receiver is unavailable"
        )
    assert store.root is None
    with pytest.raises(ValueError):
        verify_packet(packet, publisher.store_id, publisher.public)


def test_local_receiver_is_test_only(candidate_env, monkeypatch, tmp_path):
    monkeypatch.setenv("APP_ENV", "development")
    with pytest.raises(PermissionError):
        CheckpointLog.initialize(tmp_path / "not-allowed.db")


def test_override_http_requires_custodian_session_and_csrf(vault, live_service):
    import json

    store, secret, publisher, *_ = vault
    store.seal("custodian")
    publisher.down = True
    live_service["service"].store = store
    body = {
        "secret": p.encode(secret),
        "integrity_override_reason": "Authorized recovery during receiver outage",
    }
    assert portal_request(live_service, "/v1/unseal", body)[0] == 403
    assert portal_request(live_service, "/v1/unseal", body, role="workload")[0] == 403
    status, headers, response = portal_request(
        live_service, "/login", {"username": "custodian", "password": live_service["password"]}
    )
    assert status == 200
    cookie = headers["Set-Cookie"].split(";")[0]
    csrf = json.loads(response)["csrf"]
    assert portal_request(live_service, "/v1/unseal", body, cookie, "wrong")[0] == 403
    assert portal_request(live_service, "/v1/unseal", body, cookie, csrf)[0] == 200
    assert store.audit_integrity == "unverified_override"
