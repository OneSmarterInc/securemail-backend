"""Synthetic independent-checkpoint acceptance tests; never use live stores."""

import json
import secrets
import shutil
import sys
import time
import uuid

import pytest
from cryptography.exceptions import InvalidTag

from backend.keyservice.store import KeyStore


def fixture_store(tmp_path):
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "live.db", secret, backup_directory=tmp_path / "snapshots"
    )
    store.unseal(secret, "synthetic-custodian")
    org = str(uuid.uuid4())
    key = store.rotate(org, None, str(uuid.uuid4()), "synthetic-maintenance")
    context = f"secure-mail:v1:organization={org}:document=sara"
    dek = secrets.token_bytes(32)
    envelope = store.wrap(org, context, dek, key["id"], "synthetic-worker")
    return store, secret, org, context, dek, envelope


def test_old_valid_backup_is_rejected_by_external_anchor(tmp_path):
    store, secret, org, context, dek, wrapper = fixture_store(tmp_path)
    old = tmp_path / "old.sqlite3"
    store.backup(old)
    store.record_event("custodian", "external_checkpoint_boundary")
    anchor = tmp_path / "trusted.json"
    store.export_checkpoint(anchor)
    latest = tmp_path / "latest.sqlite3"
    store.backup(latest)
    with pytest.raises(ValueError, match="checkpoint"):
        KeyStore.restore(old, tmp_path / "rejected.db", secret, trusted_checkpoint=anchor)
    assert not (tmp_path / "rejected.db").exists()
    restored = KeyStore.restore(
        latest, tmp_path / "clean-machine" / "keys.db", secret, trusted_checkpoint=anchor
    )
    assert restored.root is None
    restored.unseal(secret, "synthetic-recovery")
    assert restored.unwrap(org, context, wrapper, "synthetic-worker") == dek
    restored.seal("custodian")
    with pytest.raises(ValueError):
        restored.unwrap(org, context, wrapper, "synthetic-worker")
    restored.unseal(secret, "custodian")
    assert restored.unwrap(org, context, wrapper, "synthetic-worker") == dek


@pytest.mark.parametrize(
    "damage", ["missing", "json", "oversize", "wrong_hash", "wrong_seq", "bool_seq"]
)
def test_checkpoint_failure_clears_unsealed_root(tmp_path, damage):
    store, secret, org, context, _, wrapper = fixture_store(tmp_path)
    anchor = tmp_path / "trusted.json"
    store.export_checkpoint(anchor)
    store.trusted_checkpoint = anchor
    original = anchor.read_bytes()
    if damage == "missing":
        anchor.unlink()
    elif damage == "json":
        anchor.write_text("{broken")
    elif damage == "oversize":
        anchor.write_bytes(b" " * 4097)
    else:
        value = json.loads(original)
        value[{"wrong_hash": "digest", "wrong_seq": "seq", "bool_seq": "seq"}[damage]] = {
            "wrong_hash": "0" * 64,
            "wrong_seq": 100000,
            "bool_seq": True,
        }[damage]
        anchor.write_text(json.dumps(value))
    with pytest.raises((ValueError, OSError)):
        store.unwrap(org, context, wrapper, "worker")
    assert store.root is None and store.audit_integrity == "failed"
    anchor.write_bytes(original)
    with pytest.raises(ValueError):
        store.unwrap(org, context, wrapper, "worker")
    store.unseal(secret, "custodian")
    assert len(store.unwrap(org, context, wrapper, "worker")) == 32


def test_wrong_recovery_cannot_publish_restore_and_checkpoint_is_exclusive(tmp_path):
    store, _, _, _, _, _ = fixture_store(tmp_path)
    anchor = tmp_path / "trusted.json"
    store.export_checkpoint(anchor)
    with pytest.raises(FileExistsError):
        store.export_checkpoint(anchor)
    backup = tmp_path / "backup.sqlite3"
    store.backup(backup)
    with pytest.raises(InvalidTag):
        KeyStore.restore(
            backup, tmp_path / "wrong-secret.db", secrets.token_bytes(32), trusted_checkpoint=anchor
        )
    assert not (tmp_path / "wrong-secret.db").exists()


def test_recent_rotation_keeps_backups_without_reopening_each_one(tmp_path, monkeypatch):
    store, _, org, context, dek, wrapper = fixture_store(tmp_path)
    before = set(store.backup_directory.glob("*.sqlite3"))

    def unexpected_scan(*args):
        pytest.fail("Recent snapshots cannot expire and need no retention database reads")

    monkeypatch.setattr(store, "snapshot_root", unexpected_scan)
    store.rotate(org, wrapper["key_id"], str(uuid.uuid4()), "synthetic-maintenance")
    after = set(store.backup_directory.glob("*.sqlite3"))
    assert before < after
    assert store.unwrap(org, context, wrapper, "worker") == dek


def test_expired_backup_still_requires_root_scoped_retention(tmp_path, monkeypatch):
    store, _, org, _, _, wrapper = fixture_store(tmp_path)
    version = wrapper["key_id"]
    for _ in range(3):
        version = store.rotate(org, version, str(uuid.uuid4()), "maintenance")["id"]
    recent = set(store.backup_directory.glob("*.sqlite3"))
    aged = store.backup_directory / (
        f"{time.time_ns() - 31 * 86400 * 1_000_000_000}-{uuid.uuid4()}.sqlite3"
    )
    shutil.copyfile(next(iter(recent)), aged)
    examined = []
    original = store.snapshot_root

    def inspect(path):
        examined.append(path)
        return original(path)

    monkeypatch.setattr(store, "snapshot_root", inspect)
    store.rotate(org, version, str(uuid.uuid4()), "maintenance")
    assert aged in examined and not aged.exists()
    assert all(path.exists() for path in recent)


@pytest.mark.parametrize(
    "arguments",
    [
        ["restore", "--backup", "unused", "--destination", "unused"],
        [
            "verify-root-recovery",
            "--store",
            "unused",
            "--backup-directory",
            "unused",
            "--destination",
            "unused",
            "--expected-root",
            "unused",
        ],
    ],
)
def test_recovery_cli_requires_independent_checkpoint(arguments, monkeypatch, capsys):
    from backend.keyservice import __main__ as cli

    monkeypatch.setattr(sys, "argv", ["keyservice", *arguments])

    def forbidden_prompt(*args):
        pytest.fail("Missing checkpoint must fail before requesting recovery material")

    monkeypatch.setattr(cli.getpass, "getpass", forbidden_prompt)
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert "--trusted-checkpoint" in capsys.readouterr().err
