import secrets
import sqlite3
import uuid
from pathlib import Path

import pytest

from backend.keyservice.store import KeyStore, SealedError


def initialized(tmp_path):
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "keys.sqlite3", secret, backup_directory=tmp_path / "backups"
    )
    store.unseal(secret, "custodian")
    org = str(uuid.uuid4())
    version = store.rotate(org, None, str(uuid.uuid4()), "custodian")
    return store, secret, org, version


def test_tampered_audit_cannot_replace_clean_snapshots(tmp_path):
    store, secret, org, version = initialized(tmp_path)
    for index in range(5):
        store.wrap(
            org,
            f"secure-mail:v1:organization={org}:mfa={index}",
            secrets.token_bytes(32),
            version["id"],
            "app",
        )
    snapshots = set(store.backup_directory.glob("*.sqlite3"))
    assert len(snapshots) == 6  # No three-file pruning of recent MFA checkpoints.
    original = {path: path.read_bytes() for path in snapshots}
    with sqlite3.connect(store.path) as db:
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("UPDATE audit SET digest=? WHERE seq=1", ("0" * 64,))
    for _ in range(4):
        with pytest.raises((ValueError, SealedError)):
            store.wrap(
                org,
                f"secure-mail:v1:organization={org}:mfa=bad",
                secrets.token_bytes(32),
                version["id"],
                "app",
            )
    assert store.root is None
    assert store.audit_integrity == "failed"
    assert set(store.backup_directory.glob("*.sqlite3")) == snapshots
    assert not list(store.backup_directory.glob("*.pending"))
    assert all(path.read_bytes() == contents for path, contents in original.items())
    restored = KeyStore.restore(sorted(snapshots)[-1], tmp_path / "restored.sqlite3", secret)
    restored.unseal(secret, "custodian")
    assert restored.root is not None


def test_invalid_copied_snapshot_is_not_published(tmp_path, monkeypatch):
    store, _, org, version = initialized(tmp_path)
    before = set(store.backup_directory.iterdir())
    verify = store.verify_audit
    calls = 0

    def reject_copy(db):
        nonlocal calls
        calls += 1
        verify(db)
        if calls == 2:
            raise ValueError("copied audit failed")

    monkeypatch.setattr(store, "verify_audit", reject_copy)
    with pytest.raises(ValueError, match="copied audit failed"):
        store.wrap(
            org,
            f"secure-mail:v1:organization={org}:mfa=1",
            secrets.token_bytes(32),
            version["id"],
            "app",
        )
    assert calls == 2
    assert set(store.backup_directory.iterdir()) == before


def test_retention_uses_age_daily_anchors_and_minimum_recovery_floor():
    day = 86400 * 1_000_000_000
    now = 100 * day

    def path(timestamp):
        return Path(f"{timestamp}-{uuid.uuid4()}.sqlite3")

    recent = [path(now - index * day // 20) for index in range(20)]
    anchor = path(now - 10 * day)
    later_same_day = path(now - 10 * day + 1)
    oldest = path(now - 31 * day)
    future = path(now + day)
    expired = set(
        KeyStore.expired_snapshots(recent + [anchor, later_same_day, oldest, future], now)
    )
    assert expired == {later_same_day, oldest}
    old_only = [path(now - (40 + index) * day) for index in range(5)]
    assert set(KeyStore.expired_snapshots(old_only, now)) == set(old_only[3:])
