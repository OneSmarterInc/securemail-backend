import hashlib
import secrets
import time
import uuid
from pathlib import Path
from unittest.mock import Mock

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.utils import timezone

from backend.apps.core import mail
from backend.apps.core.models import Attachment, AuditEvent, DeliveryJob
from backend.keyservice.server import Handler, Service
from backend.keyservice.store import KeyStore
from backend.tests.test_flows import compose, post, recipient_access


@pytest.mark.django_db
def test_setup_requires_explicit_token_and_is_one_time(settings):
    token = secrets.token_urlsafe(32)
    settings.SETUP_TOKEN_SHA256 = hashlib.sha256(token.encode()).hexdigest()
    body = {"email": "first@onesmarter.com", "password": "Synthetic-example-password-123!"}
    client = Client(REMOTE_ADDR="127.0.0.1", HTTP_X_REAL_IP="203.0.113.8")
    assert post(client, "/auth/setup", body).status_code == 404
    assert post(client, "/auth/setup", {**body, "setup_token": token}).status_code == 200
    assert post(client, "/auth/setup", {**body, "setup_token": token}).status_code == 409


@pytest.mark.django_db
def test_dev_inbox_requires_separate_capability(settings):
    token = secrets.token_urlsafe(32)
    settings.DEV_INBOX_TOKEN_SHA256 = hashlib.sha256(token.encode()).hexdigest()
    client = Client(REMOTE_ADDR="127.0.0.1")
    assert client.get("/api/dev/inbox").status_code == 404
    assert client.get("/api/dev/inbox", HTTP_X_DEV_INBOX_TOKEN=token).status_code == 200


@pytest.mark.django_db
def test_mfa_reset_stepup_privilege_and_session_revocation(
    admin_client, admin, staff, staff_client
):
    data = {"action": "reset_mfa", "reason": "Identity verified offline"}
    path = f"/admin/accounts/{staff.pk}"
    session = admin_client.session
    session["mfa_at"] = time.time() - 601
    session.save()
    assert post(admin_client, path, data).status_code == 403
    session["mfa_at"] = time.time()
    session.save()
    staff.mfa_secret = "old encrypted seed"
    staff.recovery_hashes = ["old recovery hash"]
    staff.save()
    key = str(uuid.uuid4())
    assert post(admin_client, path, data, key).status_code == 200
    assert post(admin_client, path, data, key).status_code == 200
    staff.refresh_from_db()
    assert not staff.mfa_confirmed and not staff.mfa_secret and not staff.recovery_hashes
    assert staff.session_version == 1
    assert staff_client.get("/api/dashboard").status_code in (401, 403)
    assert AuditEvent.objects.filter(action="account.reset_mfa").count() == 1
    assert post(admin_client, f"/admin/accounts/{admin.pk}", data).status_code == 403


@pytest.mark.django_db
def test_sender_assignment_requires_privilege(admin_client, admin):
    admin.can_manage_privileges = False
    admin.save()
    result = post(
        admin_client,
        "/admin/accounts",
        {
            "name": "New staff",
            "email": "new@onesmarter.com",
            "sender_addresses": ["ceo@onesmarter.com"],
        },
    )
    assert result.status_code == 403


@pytest.mark.django_db
@pytest.mark.parametrize("during_send", [False, True])
def test_smtp_connect_failure_vs_submission_ambiguity(
    staff_client, sender_profile, monkeypatch, during_send
):
    assert compose(staff_client).status_code == 201
    connection = Mock()
    if not during_send:
        connection.open.side_effect = ConnectionRefusedError()
    monkeypatch.setattr(
        mail.smtp_settings,
        "notification_connection",
        lambda: ("support@onesmarter.com", connection),
    )
    send = Mock(side_effect=ConnectionResetError())
    monkeypatch.setattr(mail.EmailMultiAlternatives, "send", send)
    job = DeliveryJob.objects.get()
    mail.process_job(job.pk)
    job.refresh_from_db()
    assert job.state == ("uncertain" if during_send else "retry")
    assert send.call_count == int(during_send)
    if not during_send:
        assert job.next_attempt > timezone.now()


@pytest.mark.django_db
def test_retry_is_idempotent_even_after_worker_state_changes(staff_client):
    compose(staff_client)
    job = DeliveryJob.objects.get()
    job.state = "uncertain"
    job.save()
    path, data, key = (
        f"/delivery/{job.pk}/retry",
        {"acknowledge_duplicate_risk": True},
        str(uuid.uuid4()),
    )
    assert post(staff_client, path, data, key).status_code == 200
    job.refresh_from_db()
    job.state = "provider_accepted"
    job.save()
    assert post(staff_client, path, data, key).status_code == 200
    job.refresh_from_db()
    assert job.state == "provider_accepted"
    assert AuditEvent.objects.filter(action="delivery.retry_requested").count() == 1


@pytest.mark.django_db
def test_recipient_staged_quota(staff_client, settings):
    visitor, conversation, _, _ = recipient_access(staff_client)
    settings.STAGED_UPLOAD_QUOTA_BYTES = 10

    def upload(value):
        return visitor.post(
            "/api/recipient/attachments",
            {"file": SimpleUploadedFile("sample.txt", value, content_type="text/plain")},
        )

    # Use the actual configured route.
    result = upload(b"hello!")
    assert result.status_code == 201, result.content
    assert upload(b"world!").status_code == 413
    assert Attachment.objects.filter(grant__conversation=conversation, message=None).count() == 1


def test_root_rotation_sanitizes_live_sqlite(tmp_path):
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "keys.sqlite3", secret, backup_directory=tmp_path / "backups"
    )
    store.unseal(secret, "custodian")
    result = store.rotate_root(secrets.token_bytes(32), store.root_id, "custodian")
    assert result["storage_cleanup_complete"]
    with store.transaction() as db:
        assert db.execute("PRAGMA secure_delete").fetchone()[0] == 1
    assert (
        not Path(str(store.path) + "-wal").exists()
        or Path(str(store.path) + "-wal").stat().st_size == 0
    )


def test_denials_are_batched_without_per_request_fsync(tmp_path):
    service = Service(Mock(), tmp_path / "policy.json", "https://localhost")
    handler = object.__new__(Handler)
    handler.server = Mock(service=service)
    for _ in range(1000):
        handler.audit_failure(None, "access_denied")
    assert service.store.record_event.call_count == 1
    assert service.denial_count == 999


@pytest.mark.django_db
def test_active_metadata_cache_is_bounded_and_failure_invalidates(org, settings, monkeypatch):
    from backend.apps.core import crypto, keyring
    from backend.keyservice.client import ServiceUnavailable

    key = keyring.active_key(org.pk)
    remote = Mock()
    remote.call.return_value = {"versions": [{"state": "active", "organization": str(org.pk)}]}
    monkeypatch.setattr(keyring, "service", lambda: remote)
    sync = Mock(return_value=key)
    monkeypatch.setattr(keyring, "synchronize", sync)
    keyring.clear_remote_cache()
    try:
        assert keyring.active_remote(org.pk).pk == key.pk
        assert keyring.active_remote(org.pk).pk == key.pk
        assert sync.call_count == 1
        settings.KEY_PROTECTOR = "key-service"
        remote.call.side_effect = ServiceUnavailable("rotated")
        with pytest.raises(ValueError):
            crypto.wrap(secrets.token_bytes(32), crypto.context(org.pk, "test", "cache"), key)
        remote.call.side_effect = None
        keyring.active_remote(org.pk)
        assert sync.call_count == 2
    finally:
        keyring.clear_remote_cache()
