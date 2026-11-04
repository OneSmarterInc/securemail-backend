"""Regression evidence for the October 29 v2 review."""

import json
import secrets
import smtplib
import uuid
from datetime import timedelta
from unittest.mock import Mock

import pytest
from cryptography.exceptions import InvalidTag
from django.utils import timezone

from backend.apps.core import crypto, keyring, mail
from backend.apps.core.key_migration import migrate
from backend.apps.core.models import Conversation, DeliveryJob, OTPChallenge, RecipientSession
from backend.keyservice import protocol as p
from backend.keyservice.store import KeyStore, validate_new_secret
from backend.tests.test_flows import compose, post, recipient_access


@pytest.mark.parametrize(
    "secret",
    [
        bytes(32),
        bytes([255]) * 32,
        bytes(range(32)),
        b"aB1!" * 8,
        b"human memorable secret padded!!!!",
    ],
)
def test_reject_weak_new_recovery_secret(secret):
    with pytest.raises(ValueError):
        validate_new_secret(secret)


def test_root_rotation_retains_backups_until_verified_recovery(tmp_path, monkeypatch):
    old, new = secrets.token_bytes(32), secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "store.sqlite3", old, backup_directory=tmp_path / "backups"
    )
    store.unseal(old, "custodian")
    org = str(uuid.uuid4())
    version = store.rotate(org, None, str(uuid.uuid4()), "maintenance")
    context = f"secure-mail:v1:organization={org}:file=sara"
    dek = secrets.token_bytes(32)
    wrapper = store.wrap(org, context, dek, version["id"], "app")
    old_paths = set(store.backup_directory.glob("*.sqlite3"))
    pending = store.backup_directory / f"1-{uuid.uuid4()}.pending"
    pending.write_bytes(b"Unreconciled snapshot must be retained")
    result = store.rotate_root(new, store.root_id, "custodian")
    assert not result["snapshot_cleanup_complete"]
    assert result["recovery_verification_required"]
    assert all(path.exists() for path in old_paths)
    # More checkpoints cannot prune old recovery material while proof is pending.
    for _ in range(4):
        version = store.rotate(org, version["id"], str(uuid.uuid4()), "maintenance")
    assert all(path.exists() for path in old_paths)
    root_id = store.root_id
    with pytest.raises(ValueError, match="previous root rotation"):
        store.rotate_root(secrets.token_bytes(32), root_id, "custodian")
    anchor = tmp_path / "trusted-checkpoint.json"
    store.export_checkpoint(anchor)
    store.seal("restart")
    store = KeyStore(store.path, store.backup_directory, trusted_checkpoint=anchor)
    from backend.keyservice.ownership import StoreOwnership

    owner = StoreOwnership(store.path)
    try:
        with pytest.raises(ValueError, match="Another key service owns"):
            store.verify_root_recovery(new, root_id, tmp_path / "busy.sqlite3", "custodian")
    finally:
        owner.close()
    assert all(path.exists() for path in old_paths)
    with pytest.raises(ValueError, match="Root changed"):
        store.verify_root_recovery(new, str(uuid.uuid4()), tmp_path / "stale.sqlite3", "custodian")
    assert store.custody_status()["sealed"]
    with pytest.raises(InvalidTag):
        store.verify_root_recovery(old, root_id, tmp_path / "wrong.sqlite3", "custodian")
    assert all(path.exists() for path in old_paths)
    with monkeypatch.context() as patch:

        def failed_restore(*args, trusted_checkpoint):
            assert trusted_checkpoint == anchor
            raise OSError("Restore failed")

        patch.setattr(KeyStore, "restore", failed_restore)
        with pytest.raises(OSError, match="Restore failed"):
            store.verify_root_recovery(new, root_id, tmp_path / "failed.sqlite3", "custodian")
    assert all(path.exists() for path in old_paths)
    assert store.custody_status()["recovery_verification_required"]
    result = store.verify_root_recovery(new, root_id, tmp_path / "restored.sqlite3", "custodian")
    assert result["retired_snapshots"] == 0
    assert result["off_host_evidence_required"]
    assert all(path.exists() for path in old_paths)
    assert pending.exists()
    assert store.custody_status()["recovery_verification_required"]
    restored = KeyStore(tmp_path / "restored.sqlite3")
    restored.unseal(new, "custodian")
    assert restored.unwrap(org, context, wrapper, "app") == dek


def test_mfa_replay_ledger_is_outside_application_storage(tmp_path):
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "store.sqlite3", secret, backup_directory=tmp_path / "backups"
    )
    store.unseal(secret, "custodian")
    org = str(uuid.uuid4())
    version = store.rotate(org, None, str(uuid.uuid4()), "maintenance")
    context = f"secure-mail:v1:organization={org}:mfa=42"
    old = store.wrap(org, context, secrets.token_bytes(32), version["id"], "app")
    dek = secrets.token_bytes(32)
    new = store.wrap(org, context, dek, version["id"], "app")
    with pytest.raises(ValueError, match="stale"):
        store.unwrap(org, context, old, "app")
    assert store.unwrap(org, context, new, "app") == dek
    assert store.unwrap_batch(org, [{"context": context, "wrapper": new}], "app") == [dek]
    with pytest.raises(ValueError):
        store.unwrap_batch(org, [{"context": context, "wrapper": new}] * 26, "app")
    rotated = store.rotate(org, version["id"], str(uuid.uuid4()), "maintenance")
    rewritten = store.rewrap(org, context, new, rotated["id"], "app")
    # A lost application commit must leave the previous wrapper of this enrollment usable.
    assert store.unwrap(org, context, new, "app") == dek
    assert store.unwrap(org, context, rewritten, "app") == dek
    with pytest.raises(ValueError, match="stale"):
        store.unwrap(org, context, old, "app")


@pytest.mark.django_db
def test_reverify_after_idle_and_staff_token_rotation(staff_client):
    visitor, conversation, token, _ = recipient_access(staff_client)
    assert (
        post(
            staff_client, f"/conversations/{conversation.pk}/messages", {"body": "Follow up"}
        ).status_code
        == 201
    )
    RecipientSession.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    OTPChallenge.objects.update(created_at=timezone.now() - timedelta(minutes=1))
    assert visitor.get("/api/recipient/conversation").status_code == 401
    assert post(visitor, "/recipient/code", {"token": token}).status_code == 200
    job = DeliveryJob.objects.filter(conversation=conversation).latest("created_at")
    code = mail.payload(job)["body"].split(" is ")[1][:6]
    assert post(visitor, "/recipient/verify", {"token": token, "code": code}).status_code == 200
    assert visitor.get("/api/recipient/conversation").status_code == 200


@pytest.mark.django_db
def test_absolute_session_cap_and_revoked_reverify(staff_client):
    visitor, _, token, _ = recipient_access(staff_client)
    RecipientSession.objects.update(created_at=timezone.now() - timedelta(hours=9))
    assert visitor.get("/api/recipient/conversation").status_code == 401
    session = RecipientSession.objects.get()
    session.grant.revoked_at = timezone.now()
    session.grant.save()
    assert post(visitor, "/recipient/code", {"token": token}).status_code == 404


@pytest.mark.django_db
def test_legacy_migration_does_not_block_other_records(staff_client, org):
    result = compose(staff_client)
    old = Conversation.objects.get(pk=result.json()["id"])
    envelope = json.loads(old.subject_ciphertext)
    envelope.pop("auth")
    envelope.pop("auth_v")
    old.subject_ciphertext = json.dumps(envelope)
    old.save()
    compose(staff_client)
    keyring.rotate(org)
    result = migrate(org, apply=True)
    assert result["skipped_legacy"] == 1
    assert result["updated"] > 0


@pytest.mark.django_db
def test_smtp_all_recipients_refused_is_definite_failure(staff_client, sender_profile, monkeypatch):
    compose(staff_client)
    monkeypatch.setattr(mail.smtp_settings, "connection", lambda user: (user.email, Mock()))
    monkeypatch.setattr(
        mail.EmailMultiAlternatives,
        "send",
        Mock(side_effect=smtplib.SMTPRecipientsRefused({"test@example.test": (550, b"rejected")})),
    )
    job = DeliveryJob.objects.get()
    mail.process_job(job.pk)
    job.refresh_from_db()
    assert job.state == "failed"
    assert job.error_code == "mail_recipients_refused"


@pytest.mark.django_db
def test_bulk_crypto_request_count_and_no_cross_request_cache(org, settings, monkeypatch):
    contexts = [crypto.context(org.pk, "subject", i) for i in range(51)]
    values = [crypto.encrypt(str(i).encode(), context) for i, context in enumerate(contexts)]
    originals = [json.loads(value) for value in values]
    keys = {
        json.dumps({field: value[field] for field in p.WRAPPER}, sort_keys=True): crypto.unwrap(
            value, context
        )
        for value, context in zip(originals, contexts, strict=True)
    }
    calls = []

    def call(operation, **data):
        calls.append(operation)
        assert operation == "unwrap-batch"
        return {
            "deks": [
                p.encode(keys[json.dumps(item["wrapper"], sort_keys=True)])
                for item in data["items"]
            ]
        }

    monkeypatch.setattr(keyring, "service", lambda: Mock(call=call))
    settings.KEY_PROTECTOR = "key-service"
    assert crypto.decrypt_many(list(zip(values, contexts, strict=True))) == [
        str(i).encode() for i in range(51)
    ]
    assert len(calls) == 3


@pytest.mark.django_db
def test_account_login_budget_applies_before_password_check(client, staff, monkeypatch):
    monkeypatch.setattr("backend.apps.core.auth.authenticate", lambda *a, **kw: None)
    data = {"email": staff.email, "password": "incorrect-test-password"}
    for _ in range(10):
        assert post(client, "/auth/login", data).status_code == 401
    assert post(client, "/auth/login", data).status_code == 429
    monkeypatch.setattr("backend.apps.core.auth.authenticate", lambda *a, **kw: staff)
    assert post(client, "/auth/login", data).status_code == 429


def test_no_implicit_backup_and_rollback_does_not_publish(tmp_path):
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(tmp_path / "store.sqlite3", secret)
    store.unseal(secret, "custodian")
    org = str(uuid.uuid4())
    with pytest.raises(ValueError, match="explicit"):
        store.rotate(org, None, str(uuid.uuid4()), "maintenance")
    assert store.list_versions(org) == []
    store.backup_directory = tmp_path / "backups"
    with pytest.raises(RuntimeError):
        with store.transaction() as db:
            store._checkpoint(db)
            raise RuntimeError("injected before commit")
    assert not list(store.backup_directory.iterdir())
    pending = store.backup_directory / "uncommitted.pending"
    pending.touch()
    with pytest.raises(ValueError, match="Uncommitted"):
        KeyStore.restore(pending, tmp_path / "restore.sqlite3", secret)


def test_synthetic_local_recovery_requires_explicit_environment(tmp_path, monkeypatch):
    from backend.keyservice.__main__ import main

    monkeypatch.setenv("SYNTHETIC_MODE", "false")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setattr(
        "sys.argv",
        [
            "keyservice",
            "init",
            "--store",
            str(tmp_path / "keys.sqlite3"),
            "--allow-local-recovery-synthetic",
        ],
    )
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert not (tmp_path / "keys.sqlite3").exists()


def test_revoked_peer_cannot_charge_authorized_budgets():
    from backend.keyservice.server import Handler

    service = Mock()
    service.identity.side_effect = PermissionError("revoked")
    handler = object.__new__(Handler)
    handler.server = Mock(service=service)
    handler.connection = Mock()
    handler.connection.getpeercert.return_value = b"fixture-certificate"
    handler.path = "/v1/unwrap"
    with pytest.raises(PermissionError):
        handler.peer()
    service.throttle.assert_not_called()


def test_peer_throttle_rejections_preserve_global_custodian_capacity(tmp_path, monkeypatch):
    import hashlib
    from concurrent.futures import ThreadPoolExecutor

    from backend.keyservice.server import Handler, Service

    now = 1000.0
    monkeypatch.setattr("backend.keyservice.server.time.monotonic", lambda: now)
    certificates = {"workload": b"workload-certificate", "custodian": b"custodian-certificate"}
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "identities": {
                    hashlib.sha256(cert).hexdigest(): {
                        "name": name,
                        "role": name,
                        "rate_limits": {"workload": 600},
                        "expires_at": 9999999999,
                    }
                    for name, cert in certificates.items()
                }
            }
        )
    )
    service = Service(Mock(), policy, "https://localhost")

    def peer(name, path):
        handler = object.__new__(Handler)
        handler.server = Mock(service=service)
        handler.connection = Mock()
        handler.connection.getpeercert.return_value = certificates[name]
        handler.path = path
        return handler.peer()

    for _ in range(600):
        peer("workload", "/v1/unwrap")
    assert service.rates["global:workload"][1] == 600

    def rejected(_):
        with pytest.raises(PermissionError, match="Rate limit exceeded"):
            peer("workload", "/v1/unwrap")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(rejected, range(3100)))
    assert service.rates["global:workload"][1] == 600
    for path in ("/v1/login", "/v1/unseal"):
        assert peer("custodian", path)[1]["role"] == "custodian"
    assert service.rates["global:custody"][1] == 2
    # The shared ceiling still rejects admitted peers when genuinely full.
    service.rates["global:custody"] = (now, 600)
    with pytest.raises(PermissionError, match="Rate limit exceeded"):
        peer("custodian", "/v1/unseal")
    assert service.rates["global:custody"][1] == 600
    now += 60
    peer("workload", "/v1/unwrap")
    assert service.rates["global:workload"][1] == 1


def test_denial_final_window_retains_identity(tmp_path):
    from backend.keyservice.server import Handler, Service

    service = Service(Mock(), tmp_path / "policy", "https://localhost")
    handler = object.__new__(Handler)
    handler.server = Mock(service=service)
    for _ in range(3):
        handler.audit_failure({"name": "revoked-worker"}, "access_denied")
    service.flush_denials(force=True)
    assert service.store.record_event.call_args.args == (
        "revoked-worker",
        "denial_batch:access_denied:count=2",
    )
    assert not service.denials


@pytest.mark.django_db
def test_mfa_reset_requires_email_recovery(admin_client, staff):
    assert (
        post(
            admin_client,
            f"/admin/accounts/{staff.pk}",
            {"action": "reset_mfa", "reason": "Identity verified"},
        ).status_code
        == 200
    )
    staff.refresh_from_db()
    assert not staff.has_usable_password()
    from backend.apps.core.models import StaffInvitation

    assert StaffInvitation.objects.filter(
        user=staff, purpose="password_recovery", consumed_at=None
    ).exists()


@pytest.mark.django_db
def test_compose_replay_after_sender_permission_change(staff_client, staff):
    data = {
        "sender": staff.email,
        "to": ["sara@example.test"],
        "subject": "Fixture",
        "mode": "secure_request",
        "body": "",
        "expiry_days": 7,
    }
    key = str(uuid.uuid4())
    first = post(staff_client, "/conversations", data, key)
    assert first.status_code == 201
    staff.sender_addresses = []
    staff.save()
    replay = post(staff_client, "/conversations", data, key)
    assert replay.status_code == 200
    assert replay.json()["id"] == first.json()["id"]
    assert Conversation.objects.count() == 1
