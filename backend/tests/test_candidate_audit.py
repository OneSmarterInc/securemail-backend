"""Disposable RP-04/RP-05 candidate tests; no independent-review claim."""

import hashlib
import json
import secrets
import sqlite3
import time
import uuid
from contextlib import closing

import pytest
from cryptography.exceptions import InvalidSignature

from backend.keyservice import protocol as p
from backend.keyservice.candidate_audit import CandidateKeyStore, meta_values
from backend.keyservice.checkpoints import CheckpointLog, packet_hash
from backend.keyservice.store import KeyStore


class LocalPublisher:
    """Injected receiver boundary; transport is tested separately, not bypassed in runtime."""

    def __init__(self, log, public, store_id):
        self.log, self.public, self.store_id = log, public, store_id
        self.down = False
        self.lose_ack = False

    def latest(self):
        if self.down:
            raise OSError("synthetic receiver unavailable")
        return self.log.latest(self.store_id)

    def publish(self, packet):
        if self.down:
            raise OSError("synthetic receiver unavailable")
        self.log.accept(self.store_id, packet)
        if self.lose_ack is True or self.lose_ack == packet["record"]["event"]:
            self.lose_ack = False
            raise OSError("synthetic lost acknowledgement")


@pytest.fixture
def candidate_env(monkeypatch):
    monkeypatch.setenv("KEY_SERVICE_AUDIT_CANDIDATE", "true")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SYNTHETIC_MODE", "true")
    monkeypatch.delenv("KEY_SERVICE_CHECKPOINT_CONFIG", raising=False)


def enroll(store, tmp_path):
    with closing(sqlite3.connect(store.path)) as db:
        meta = meta_values(db)
    receiver = CheckpointLog.initialize(tmp_path / "receiver.db")
    receiver.enroll(meta["checkpoint_pub"], p.parse_object(meta["candidate_genesis"]))
    store.publisher = LocalPublisher(receiver, meta["checkpoint_pub"], meta["store_id"])
    return store.publisher


@pytest.fixture
def vault(tmp_path, candidate_env):
    secret = secrets.token_bytes(32)
    store = CandidateKeyStore.initialize(
        tmp_path / "store.db", secret, backup_directory=tmp_path / "backups"
    )
    publisher = enroll(store, tmp_path)
    store.unseal(secret, "custodian")
    org = str(uuid.uuid4())
    version = store.rotate(org, None, str(uuid.uuid4()), "maintenance")
    context = f"secure-mail:v1:organization={org}:document=sara"
    dek = secrets.token_bytes(32)
    wrapper = store.wrap(org, context, dek, version["id"], "worker")
    return store, secret, publisher, org, context, dek, wrapper


def rewrite_sha_history(path, *, strip_macs=False):
    with closing(sqlite3.connect(path)) as db, db:
        db.row_factory = sqlite3.Row
        db.execute("DROP TRIGGER audit_no_update")
        previous = "0" * 64
        for row in db.execute("SELECT * FROM audit ORDER BY seq").fetchall():
            body = p.parse_object(row["body"])
            body["actor"] = "forged-actor"
            body["previous"] = previous
            digest = hashlib.sha256(p.canonical(body)).hexdigest()
            db.execute(
                "UPDATE audit SET body=?,digest=? WHERE seq=?",
                (p.canonical(body).decode(), digest, row["seq"]),
            )
            previous = digest
        if strip_macs:
            db.execute("UPDATE audit SET mac=NULL,key_id=NULL,next_mac=NULL")


@pytest.mark.parametrize("strip_macs", [False, True])
def test_rp05_coherent_audit_rewrite_is_detected(vault, strip_macs):
    store, secret, *_ = vault
    store.seal("custodian")
    rewrite_sha_history(store.path, strip_macs=strip_macs)
    with pytest.raises(ValueError, match="MAC|genesis|gap"):
        store.unseal(secret, "custodian")
    assert store.root is None and store.audit_integrity == "failed"


def test_rp04_restore_of_older_snapshot_is_detected(vault, tmp_path):
    store, secret, publisher, org, *_ = vault
    old = tmp_path / "old.db"
    store.backup(old)
    store.seal("custodian")
    with pytest.raises(ValueError, match="checkpoint"):
        CandidateKeyStore.restore(old, tmp_path / "rejected.db", secret, publisher=publisher)
    assert not (tmp_path / "rejected.db").exists()
    current = tmp_path / "current.db"
    store.backup(current)
    before = packet_hash(publisher.latest())
    restored = CandidateKeyStore.restore(
        current, tmp_path / "restored.db", secret, publisher=publisher
    )
    assert restored.root is None
    assert packet_hash(publisher.latest()) == before  # Verification does not fork the live log.


def test_published_tail_truncation_and_row_deletion_rejected(vault):
    store, secret, *_ = vault
    store.seal("custodian")
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("DROP TRIGGER audit_no_delete")
        db.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)")
    with pytest.raises(ValueError, match="checkpoint"):
        store.unseal(secret, "custodian")
    assert store.root is None


def test_root_rotation_preserves_authentication_keys_and_old_document(vault, tmp_path):
    store, _, publisher, org, context, dek, wrapper = vault
    with closing(sqlite3.connect(store.path)) as db:
        before = meta_values(db)
    new_secret = secrets.token_bytes(32)
    result = store.rotate_root(new_secret, store.root_id, "custodian")
    with closing(sqlite3.connect(store.path)) as db:
        after = meta_values(db)
    for name in ("store_id", "audit_key_id", "checkpoint_key_id", "checkpoint_pub"):
        assert before[name] == after[name]
    assert before["audit_keys"] != after["audit_keys"]
    assert publisher.latest()["record"]["previous_root_id"] == before["root_id"]
    assert publisher.latest()["record"]["root_id"] == result["root_id"]
    store.seal("custodian")
    store.unseal(new_secret, "custodian")
    assert store.unwrap(org, context, wrapper, "worker") == dek
    proof = store.verify_root_recovery(
        new_secret, result["root_id"], tmp_path / "recovery.db", "custodian"
    )
    assert proof["root_id"] == result["root_id"]


def test_audit_key_rotation_verifies_both_proofs_and_historic_rows(vault):
    store, secret, publisher, org, context, dek, wrapper = vault
    ident = store.rotate_audit_key("custodian")
    assert publisher.latest()["record"]["audit_key_id"] == ident
    store.seal("custodian")
    store.unseal(secret, "custodian")
    assert store.unwrap(org, context, wrapper, "worker") == dek
    store._clear()
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("UPDATE audit SET next_mac=? WHERE next_mac IS NOT NULL", ("0" * 64,))
    with pytest.raises(ValueError, match="cross-authentication"):
        store.unseal(secret, "custodian")


def test_sealed_gap_is_attested_but_not_claimed_authentic(vault):
    store, secret, *_ = vault
    store.seal("custodian")
    store.record_event("custodian", "login_success")
    # Explicit R2 residual: coherent changes to an unexported unsigned gap are possible.
    with closing(sqlite3.connect(store.path)) as db, db:
        db.row_factory = sqlite3.Row
        db.execute("DROP TRIGGER audit_no_update")
        row = db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        body = p.parse_object(row["body"])
        body["actor"] = "rewritten-untrusted-observation"
        db.execute(
            "UPDATE audit SET body=?,digest=? WHERE seq=?",
            (p.canonical(body).decode(), hashlib.sha256(p.canonical(body)).hexdigest(), row["seq"]),
        )
    store.unseal(secret, "custodian")
    with store.transaction() as db:
        store.verify_audit(db)
        rows = [p.parse_object(row[0]) for row in db.execute("SELECT body FROM audit")]
    gap = next(body for body in rows if body["operation"] == "sealed_gap_attestation")
    assert gap["details"]["trusted"] is False


def test_crash_sealed_login_observations_do_not_require_plaintext_key(vault):
    store, secret, *_ = vault
    store._clear()  # Simulate restart without a seal event.
    store.record_event("custodian", "login_success")
    with closing(sqlite3.connect(store.path)) as db:
        assert db.execute("SELECT COUNT(*) FROM sealed_pending").fetchone()[0] == 1
    store.unseal(secret, "custodian")
    with store.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM sealed_pending").fetchone()[0] == 0
        store.verify_audit(db)


def test_receiver_outage_wrap_allowed_mutation_and_unseal_refused(vault):
    store, secret, publisher, org, context, dek, wrapper = vault
    publisher.down = True
    assert store.unwrap(org, context, wrapper, "worker") == dek
    version = store.list_versions(org, active=True)[0]
    assert store.wrap(org, context, dek, version["id"], "worker")
    with pytest.raises(OSError):
        store.rotate(org, version["id"], str(uuid.uuid4()), "maintenance")
    assert store.root is None
    with pytest.raises(OSError):
        store.unseal(secret, "custodian")
    assert store.root is None
    publisher.down = False
    store.unseal(secret, "custodian")
    assert store.list_versions(org, active=True)[0]["id"] == version["id"]


def test_lost_ack_seals_and_retains_exact_reconcilable_snapshot(vault, tmp_path):
    store, secret, publisher, org, *_ = vault
    version = store.list_versions(org, active=True)[0]
    publisher.lose_ack = True
    with pytest.raises(OSError, match="acknowledgement"):
        store.rotate(org, version["id"], str(uuid.uuid4()), "maintenance")
    assert store.root is None
    pending = list(store.backup_directory.glob("*.pending"))
    assert len(pending) == 1
    with pytest.raises(ValueError, match="checkpoint"):
        store.unseal(secret, "custodian")
    reconciled = CandidateKeyStore.restore(
        pending[0], tmp_path / "reconciled.db", secret, publisher=publisher, reconcile_pending=True
    )
    reconciled.backup_directory = tmp_path / "reconciled-backups"
    reconciled.unseal(secret, "custodian")
    assert reconciled.list_versions(org, active=True)[0]["id"] != version["id"]


def test_receiver_signature_fork_replay_and_append_only_guards(vault):
    store, _, publisher, *_ = vault
    previous = publisher.latest()
    store.seal("custodian")
    latest = publisher.latest()
    publisher.publish(latest)  # exact retry is idempotent
    with pytest.raises(ValueError, match="rollback"):
        publisher.publish(previous)
    forged = json.loads(json.dumps(latest))
    forged["record"]["seq"] += 1
    with pytest.raises(InvalidSignature):
        publisher.publish(forged)
    with (
        closing(sqlite3.connect(publisher.log.path)) as db,
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
    ):
        db.execute("DELETE FROM checkpoints")


def test_periodic_export_outage_and_retry(vault):
    store, _, publisher, org, context, dek, wrapper = vault
    publisher.down = True
    store.last_export_time = time.monotonic() - 301
    store.tick()
    assert store.export_pending and store.root is not None
    assert store.unwrap(org, context, wrapper, "worker") == dek
    publisher.down = False
    store.next_export_retry = 0
    store.tick()
    assert not store.export_pending
    assert publisher.latest()["record"]["seq"] == store.last_export_seq


def test_migration_copies_legacy_and_requires_offline_enrollment(tmp_path, candidate_env):
    secret = secrets.token_bytes(32)
    legacy = KeyStore.initialize(tmp_path / "legacy.db", secret)
    legacy.unseal(secret, "custodian")
    legacy.seal("custodian")
    anchor = tmp_path / "trusted.json"
    legacy.export_checkpoint(anchor)
    migrated = CandidateKeyStore.migrate(
        legacy.path,
        tmp_path / "candidate.db",
        secret,
        trusted_checkpoint=anchor,
        backup_directory=tmp_path / "backups",
    )
    with closing(sqlite3.connect(legacy.path)) as db:
        assert "audit_format" not in meta_values(db)
    with pytest.raises(ValueError, match="enrollment"):
        migrated.unseal(secret, "custodian")
    enroll(migrated, tmp_path)
    migrated.unseal(secret, "custodian")
    with migrated.transaction() as db:
        migrated.verify_audit(db)


@pytest.mark.parametrize("environment", [None, "production", "staging"])
def test_candidate_cannot_run_outside_explicit_synthetic_scope(tmp_path, monkeypatch, environment):
    monkeypatch.setenv("KEY_SERVICE_AUDIT_CANDIDATE", "true")
    monkeypatch.setenv("SYNTHETIC_MODE", "true")
    monkeypatch.delenv("APP_ENV", raising=False)
    if environment:
        monkeypatch.setenv("APP_ENV", environment)
    with pytest.raises(PermissionError):
        CandidateKeyStore.initialize(tmp_path / "not-created.db", secrets.token_bytes(32))
    assert not (tmp_path / "not-created.db").exists()


def test_candidate_store_refuses_legacy_open_and_flag_removal(vault, monkeypatch):
    store, *_ = vault
    with pytest.raises(ValueError, match="candidate"):
        KeyStore(store.path)
    monkeypatch.delenv("KEY_SERVICE_AUDIT_CANDIDATE")
    with pytest.raises(PermissionError):
        CandidateKeyStore(store.path)


def test_stripped_mac_outside_sealed_gap_is_rejected(vault):
    store, secret, *_ = vault
    store._clear()
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("UPDATE audit SET mac=NULL,key_id=NULL WHERE seq=(SELECT MAX(seq) FROM audit)")
    with pytest.raises(ValueError, match="Missing audit MAC"):
        store.unseal(secret, "custodian")


def test_live_rollback_below_cached_checkpoint_refuses_key_use(vault):
    store, _, _, org, context, _, wrapper = vault
    store.rotate_audit_key("custodian")
    # A local suffix can retain valid HMACs but must not precede an acknowledged head.
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("DROP TRIGGER audit_no_delete")
        head = db.execute("SELECT MAX(seq) FROM audit").fetchone()[0]
        body = p.parse_object(
            db.execute("SELECT body FROM audit WHERE seq=?", (head,)).fetchone()[0]
        )
        db.execute("DELETE FROM audit WHERE seq=?", (head,))
        db.execute(
            "UPDATE meta SET value=? WHERE name='audit_key_id'", (body["details"]["old_id"],)
        )
    with pytest.raises(ValueError, match="Cached external checkpoint|protected-state"):
        store.unwrap(org, context, wrapper, "worker")
    assert store.root is None


def test_seal_failure_clears_root_even_when_receiver_is_unavailable(vault):
    store, _, publisher, *_ = vault
    publisher.down = True
    with pytest.raises(OSError):
        store.seal("custodian")
    assert store.root is None and store.root_id is None


def test_correctly_signed_but_forked_checkpoint_is_rejected(vault):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from backend.keyservice.candidate_audit import audit_aad
    from backend.keyservice.checkpoints import DOMAIN
    from backend.keyservice.store import recover

    store, _, publisher, *_ = vault
    forged = publisher.latest()
    with closing(sqlite3.connect(store.path)) as db:
        meta = meta_values(db)
    seed = recover(
        store.root,
        meta["checkpoint_key"],
        32,
        audit_aad(meta, meta["checkpoint_key_id"], "checkpoint-sign"),
    )
    forged["record"]["seq"] += 1
    forged["record"]["previous_checkpoint_sha256"] = "0" * 64
    forged["signature"] = p.encode(
        Ed25519PrivateKey.from_private_bytes(seed).sign(DOMAIN + p.canonical(forged["record"]))
    )
    with pytest.raises(ValueError, match="fork"):
        publisher.publish(forged)


def test_deleted_row_and_recomputed_sequence_digest_cannot_repair_macs(vault):
    store, secret, *_ = vault
    store.seal("custodian")
    with closing(sqlite3.connect(store.path)) as db, db:
        db.row_factory = sqlite3.Row
        rows = [dict(row) for row in db.execute("SELECT * FROM audit ORDER BY seq")]
        db.execute("DROP TRIGGER audit_no_delete")
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("DELETE FROM audit")
        previous = "0" * 64
        for seq, row in enumerate([row for row in rows if row["seq"] != 3], 1):
            body = p.parse_object(row["body"])
            body["previous"] = previous
            raw = p.canonical(body)
            previous = hashlib.sha256(raw).hexdigest()
            db.execute(
                "INSERT INTO audit VALUES (?,?,?,?,?,?)",
                (seq, raw.decode(), previous, row["mac"], row["key_id"], row["next_mac"]),
            )
    with pytest.raises(ValueError, match="MAC"):
        store.unseal(secret, "custodian")


def test_one_hundred_row_checkpoint_trigger(vault):
    store, _, publisher, *_ = vault
    start = publisher.latest()["record"]["seq"]
    for _ in range(99):  # fixture already has one unexported wrap row
        store.record_event("custodian", "synthetic_observation")
    assert publisher.latest()["record"]["seq"] == start + 100


def test_unexported_valid_tail_truncation_is_explicit_residual(vault):
    store, secret, *_ = vault
    store._clear()
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("DROP TRIGGER audit_no_delete")
        db.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)")
    # No external observer saw the last wrap row. HMAC chains do not prove freshness.
    # This test documents the boundary instead of claiming T3 is fully solved.
    store.unseal(secret, "custodian")
    assert store.root is not None


def test_root_rotation_lost_ack_reconciles_only_with_new_custody(vault, tmp_path):
    store, old_secret, publisher, org, context, dek, wrapper = vault
    new_secret = secrets.token_bytes(32)
    publisher.lose_ack = "rotate_root"
    with pytest.raises(OSError):
        store.rotate_root(new_secret, store.root_id, "custodian")
    assert store.root is None
    pending = list(store.backup_directory.glob("*.pending"))
    assert len(pending) == 1
    with pytest.raises(ValueError, match="checkpoint"):
        store.unseal(old_secret, "custodian")
    restored = CandidateKeyStore.restore(
        pending[0],
        tmp_path / "new-root-reconciled.db",
        new_secret,
        publisher=publisher,
        reconcile_pending=True,
    )
    restored.backup_directory = tmp_path / "new-root-backups"
    restored.unseal(new_secret, "custodian")
    assert restored.unwrap(org, context, wrapper, "worker") == dek


def test_interrupted_copy_migration_rolls_back_schema_and_preserves_source(
    tmp_path, candidate_env, monkeypatch
):
    from backend.keyservice import candidate_audit

    secret = secrets.token_bytes(32)
    source = KeyStore.initialize(tmp_path / "source.db", secret)
    source.unseal(secret, "custodian")
    source.seal("custodian")
    anchor = tmp_path / "anchor.json"
    source.export_checkpoint(anchor)
    original_put = candidate_audit.put_meta

    def fail_partway(db, name, value):
        if name == "checkpoint_key":
            raise OSError("synthetic migration interruption")
        original_put(db, name, value)

    monkeypatch.setattr(candidate_audit, "put_meta", fail_partway)
    destination = tmp_path / "copy.db"
    with pytest.raises(OSError, match="interruption"):
        CandidateKeyStore.migrate(
            source.path,
            destination,
            secret,
            trusted_checkpoint=anchor,
            backup_directory=tmp_path / "backups",
        )
    for path in (source.path, destination):
        with closing(sqlite3.connect(path)) as db:
            db.row_factory = sqlite3.Row
            assert "audit_format" not in meta_values(db)
            assert "mac" not in {row[1] for row in db.execute("PRAGMA table_info(audit)")}
            KeyStore.verify_audit(db)


def test_idle_receiver_recovery_clears_pending_status_without_new_rows(vault):
    store, _, publisher, *_ = vault
    store.rotate_audit_key("custodian")
    publisher.down = True
    store.last_export_time = time.monotonic() - 301
    store.tick()
    assert store.export_pending
    publisher.down = False
    store.next_export_retry = 0
    store.tick()
    assert not store.export_pending


def test_old_key_state_spliced_under_authentic_new_audit_is_rejected(vault):
    store, secret, _, org, *_ = vault
    with closing(sqlite3.connect(store.path)) as db:
        old_versions = db.execute("SELECT * FROM versions").fetchall()
        old_requests = db.execute("SELECT * FROM requests").fetchall()
    active = store.list_versions(org, active=True)[0]["id"]
    store.rotate(org, active, str(uuid.uuid4()), "maintenance")
    store._clear()
    # All audit MACs/signatures are intact. Replay only genuine older key state.
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("DELETE FROM versions")
        db.executemany("INSERT INTO versions VALUES (?,?,?,?)", old_versions)
        db.execute("DELETE FROM requests")
        db.executemany("INSERT INTO requests VALUES (?,?,?)", old_requests)
    with pytest.raises(ValueError, match="protected-state"):
        store.unseal(secret, "custodian")
    assert store.root is None


def test_periodic_publisher_cannot_bless_tampered_state(vault):
    store, _, publisher, *_ = vault
    before = packet_hash(publisher.latest())
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("UPDATE versions SET state='decrypt_only'")
    store.last_export_time = time.monotonic() - 301
    with pytest.raises(ValueError, match="protected-state"):
        store.tick()
    assert store.root is None
    assert packet_hash(publisher.latest()) == before
