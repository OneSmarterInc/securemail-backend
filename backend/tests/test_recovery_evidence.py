import secrets
import sqlite3
import time
import uuid
from contextlib import closing

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.keyservice import protocol as p
from backend.keyservice.recovery_evidence import DOMAIN, file_digest
from backend.keyservice.store import KeyStore


def setup_recovery(tmp_path, monkeypatch):
    old, new = secrets.token_bytes(32), secrets.token_bytes(32)
    store = KeyStore.initialize(tmp_path / "live.db", old, backup_directory=tmp_path / "backups")
    store.unseal(old, "custodian")
    org = str(uuid.uuid4())
    store.rotate(org, None, str(uuid.uuid4()), "maintenance")
    old_paths = set(store.backup_directory.glob("*.sqlite3"))
    store.rotate_root(new, store.root_id, "custodian")
    root_id = store.root_id
    old_paths = {
        path
        for path in store.backup_directory.glob("*.sqlite3")
        if store.snapshot_root(path) != root_id
    }
    store.seal("custodian")
    backup = tmp_path / "downloaded-remote-copy.db"
    store.backup(backup)
    keys = {name: Ed25519PrivateKey.generate() for name in ("receiver", "drill")}
    trust = {
        "key_host_id": "key-host",
        "receiver_id": "backup-host",
        "restore_host_ids": ["fresh-host"],
        "issuers": {
            "receiver": {
                "kind": "off_host_backup",
                "public": p.encode(keys["receiver"].public_key().public_bytes_raw()),
            },
            "drill": {
                "kind": "clean_machine_restore",
                "public": p.encode(keys["drill"].public_key().public_bytes_raw()),
            },
        },
    }
    trust_path = tmp_path / "operator-trust.json"
    trust_path.write_bytes(p.canonical(trust))
    monkeypatch.setenv("KEY_SERVICE_RECOVERY_TRUST", str(trust_path))
    now = int(time.time())
    record = {
        "v": 1,
        "root_id": root_id,
        "backup_sha256": file_digest(backup),
        "backup_id": "immutable-copy-123",
        "source_host_id": "key-host",
        "receiver_id": "backup-host",
        "issued_at": now - 1,
        "expires_at": now + 3600,
    }
    bundle = {
        "receipt": {"issuer": "receiver", "record": {**record, "kind": "off_host_backup"}},
        "restore": {
            "issuer": "drill",
            "record": {
                **record,
                "kind": "clean_machine_restore",
                "restore_host_id": "fresh-host",
                "restore_id": "drill-456",
                "documents_verified": 3,
            },
        },
    }
    return store, new, root_id, old_paths, backup, keys, bundle


def sign_bundle(path, keys, bundle):
    for packet in bundle.values():
        packet["signature"] = p.encode(
            keys[packet["issuer"]].sign(DOMAIN + p.canonical(packet["record"]))
        )
    path.write_bytes(p.canonical(bundle))


def test_same_host_drill_cannot_retire_old_root_snapshots(tmp_path, monkeypatch):
    store, secret, root_id, old_paths, *_ = setup_recovery(tmp_path, monkeypatch)
    result = store.verify_root_recovery(secret, root_id, tmp_path / "same-host.db", "custodian")
    assert result["retired_snapshots"] == 0 and not result["retirement_authorized"]
    assert all(path.exists() for path in old_paths)
    assert store.custody_status()["recovery_verification_required"]


def test_signed_remote_copy_and_clean_machine_proof_allow_retirement(tmp_path, monkeypatch):
    store, secret, root_id, old_paths, backup, keys, bundle = setup_recovery(tmp_path, monkeypatch)
    evidence = tmp_path / "evidence.json"
    sign_bundle(evidence, keys, bundle)
    result = store.verify_root_recovery(
        secret,
        root_id,
        tmp_path / "verified.db",
        "custodian",
        off_host_backup=backup,
        recovery_evidence=evidence,
    )
    assert result["retirement_authorized"] and result["retired_snapshots"] == len(old_paths)
    assert all(not path.exists() for path in old_paths)
    assert not store.custody_status()["recovery_verification_required"]


@pytest.mark.parametrize(
    "damage",
    [
        "same_host",
        "missing_restore",
        "wrong_digest",
        "wrong_root",
        "expired",
        "no_documents",
        "forged_signature",
        "missing_trust",
    ],
)
def test_retirement_refused_without_valid_independent_proof(tmp_path, monkeypatch, damage):
    store, secret, root_id, old_paths, backup, keys, bundle = setup_recovery(tmp_path, monkeypatch)
    record = bundle["restore"]["record"]
    if damage == "same_host":
        record["restore_host_id"] = "key-host"
    elif damage == "missing_restore":
        del bundle["restore"]
    elif damage == "wrong_digest":
        for item in bundle.values():
            item["record"]["backup_sha256"] = "0" * 64
    elif damage == "wrong_root":
        record["root_id"] = str(uuid.uuid4())
    elif damage == "expired":
        record["expires_at"] = int(time.time()) - 10
    elif damage == "no_documents":
        record["documents_verified"] = 0
    elif damage == "missing_trust":
        monkeypatch.delenv("KEY_SERVICE_RECOVERY_TRUST")
    evidence = tmp_path / "evidence.json"
    sign_bundle(evidence, keys, bundle)
    if damage == "forged_signature":
        bundle["restore"]["signature"] = p.encode(bytes(64))
        evidence.write_bytes(p.canonical(bundle))
    with pytest.raises((ValueError, InvalidSignature)):
        store.verify_root_recovery(
            secret,
            root_id,
            tmp_path / "rejected.db",
            "custodian",
            off_host_backup=backup,
            recovery_evidence=evidence,
        )
    assert all(path.exists() for path in old_paths)
    with closing(sqlite3.connect(store.path)) as db:
        assert db.execute("SELECT 1 FROM meta WHERE name='root_recovery_pending'").fetchone()
