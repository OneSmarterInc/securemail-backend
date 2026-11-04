"""Regression coverage for the internal encryption review; synthetic material only."""

import hashlib
import secrets
import sqlite3
import subprocess
import sys
import uuid

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from backend.apps.core import crypto
from backend.keyservice import protocol as p
from backend.keyservice.ownership import StoreOwnership
from backend.keyservice.server import Service
from backend.keyservice.store import KeyStore, SealedError


def test_service_mode_rejects_local_legacy_reads(settings, monkeypatch):
    settings.SYNTHETIC_MODE = True
    settings.ALLOW_LEGACY_SYNTHETIC_READS = True
    settings.KEY_PROTECTOR = "key-service"
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    context = crypto.context(uuid.uuid4(), "document", uuid.uuid4())
    envelope = p.canonical(
        {
            "v": 1,
            "provider": "synthetic-aes256gcm",
            "key_id": "local-v1",
            "key": p.encode(aes_key_wrap(crypto._local_key(), key)),
            "nonce": p.encode(nonce),
            "data": p.encode(
                AESGCM(key).encrypt(nonce, b"synthetic Sara document", context.encode())
            ),
        }
    ).decode()

    def unavailable_service():
        raise ValueError("Synthetic service is unavailable")

    monkeypatch.setattr(crypto.keyring, "service", unavailable_service)
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(envelope, context)


def test_seal_applies_to_every_instance_of_store(tmp_path):
    secret = secrets.token_bytes(32)
    first = KeyStore.initialize(
        tmp_path / "keys.sqlite3", secret, backup_directory=tmp_path / "backups"
    )
    first.unseal(secret, "custodian")
    org = str(uuid.uuid4())
    key = first.rotate(org, None, str(uuid.uuid4()), "maintenance")
    context = crypto.context(org, "document", uuid.uuid4())
    dek = secrets.token_bytes(32)
    wrapper = first.wrap(org, context, dek, key["id"], "worker")
    second = KeyStore(first.path)
    second.unseal(secret, "custodian")
    first.seal("custodian")
    assert first.status()["sealed"]
    with pytest.raises(SealedError):
        second.unwrap(org, context, wrapper, "worker")
    assert second.status()["sealed"]
    second.unseal(secret, "custodian")
    assert second.unwrap(org, context, wrapper, "worker") == dek


def test_rotation_history_fits_versions_response(tmp_path):
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "keys.sqlite3", secret, backup_directory=tmp_path / "backups"
    )
    store.unseal(secret, "custodian")
    org = str(uuid.uuid4())
    active = None
    for _ in range(600):
        active = store.rotate(org, active, str(uuid.uuid4()), "maintenance")["id"]
    service = Service(store, tmp_path / "unused-policy.json", "https://localhost")
    identity = {"name": "worker", "operations": ["versions"], "organizations": [org]}
    page = service.dispatch("versions", {"organization": org}, identity)
    payload = p.canonical(page)
    assert len(payload) <= 1024 * 1024, f"Response is {len(payload)} bytes"
    selected = service.dispatch("versions", {"organization": org, "active": True}, identity)
    assert [row["id"] for row in selected["versions"]] == [active]
    assert selected["next_cursor"] is None
    identifiers = []
    after = ""
    while True:
        page = service.dispatch("versions", {"organization": org, "after": after}, identity)
        assert len(page["versions"]) <= 100
        identifiers.extend(row["id"] for row in page["versions"])
        after = page["next_cursor"]
        if after is None:
            break
    assert len(identifiers) == len(set(identifiers)) == 600
    with pytest.raises(PermissionError):
        service.dispatch("versions", {"organization": str(uuid.uuid4()), "active": True}, identity)


def test_unseal_detects_modified_audit_history(tmp_path):
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "keys.sqlite3", secret, backup_directory=tmp_path / "backups"
    )
    store.unseal(secret, "custodian")
    store.seal("custodian")
    # Model a modified backup / privileged filesystem writer, not a portal user.
    db = sqlite3.connect(store.path)
    try:
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("UPDATE audit SET body=? WHERE seq=1", ('{"tampered":true}',))
        db.commit()
    finally:
        db.close()
    with pytest.raises(ValueError, match="audit integrity"):
        store.unseal(secret, "custodian")
    assert store.status()["sealed"]
    assert store.status()["audit_integrity"] == "failed"


def test_service_ownership_across_processes_and_crash(tmp_path):
    path = tmp_path / "store.sqlite3"
    owner = StoreOwnership(path)
    script = (
        "import os,sys; from pathlib import Path; "
        "from backend.keyservice.ownership import StoreOwnership; "
        "lock=StoreOwnership(Path(sys.argv[1])); os._exit(0)"
    )
    try:
        blocked = subprocess.run(
            [sys.executable, "-c", script, str(path)], capture_output=True, timeout=15
        )
        assert blocked.returncode != 0
        assert b"Another key service owns" in blocked.stderr
    finally:
        owner.close()
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(path)], capture_output=True, timeout=15
    )
    assert crashed.returncode == 0, crashed.stderr
    # os._exit skipped cleanup; the operating system must still release ownership.
    recovered = StoreOwnership(path)
    recovered.close()


@pytest.mark.parametrize("active,after", [(1, ""), (True, str(uuid.uuid4())), (False, "bad")])
def test_version_query_rejects_invalid_parameters(tmp_path, active, after):
    store = KeyStore.initialize(
        tmp_path / "keys.sqlite3", secrets.token_bytes(32), backup_directory=tmp_path / "backups"
    )
    with pytest.raises(ValueError):
        store.list_versions(str(uuid.uuid4()), active=active, after=after)


@pytest.mark.parametrize("damage", ["link", "gap", "json"])
def test_audit_corruption_clears_an_already_unsealed_root(tmp_path, damage):
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "keys.sqlite3", secret, backup_directory=tmp_path / "backups"
    )
    store.unseal(secret, "custodian")
    store.record_event("worker", "test_event")
    store.record_event("worker", "test_event")
    db = sqlite3.connect(store.path)
    try:
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("DROP TRIGGER audit_no_delete")
        if damage == "gap":
            db.execute("DELETE FROM audit WHERE seq=2")
        else:
            body = p.canonical({"previous": "f" * 64}).decode() if damage == "link" else "["
            db.execute(
                "UPDATE audit SET body=?,digest=? WHERE seq=2",
                (body, hashlib.sha256(body.encode()).hexdigest()),
            )
        db.commit()
    finally:
        db.close()
    with pytest.raises(ValueError):
        store.unseal(secret, "custodian")
    assert store.root is None
    assert store.status()["audit_integrity"] == "failed"
