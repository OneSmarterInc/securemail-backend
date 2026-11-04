import time
from datetime import timedelta
from unittest.mock import Mock

import pytest

from backend.apps.core import audit as archive
from backend.apps.core.models import AuditArchive, AuditBatch, AuditEvent
from backend.apps.core.services import audit, record_login_failure
from backend.tests.test_readiness import Archive


@pytest.mark.django_db
def test_archive_drains_5000_events_in_five_objects(org, settings, monkeypatch):
    settings.AUDIT_BUCKET, settings.AUDIT_RETENTION_DAYS = "synthetic", 30
    settings.AUDIT_ARCHIVE_BATCH_SIZE = 1000
    settings.AUDIT_ARCHIVE_MAX_BATCHES = 2
    fake = Archive()
    put = Mock(wraps=fake.put_object)
    fake.put_object = put
    monkeypatch.setattr(archive.boto3, "client", lambda *a, **k: fake)
    AuditEvent.objects.bulk_create(
        [
            AuditEvent(
                organization=org,
                sequence=i,
                actor_id="system",
                actor_label="System",
                actor_role="system",
                action="test.load",
                target_type="test",
                target_id=str(i),
            )
            for i in range(1, 5001)
        ]
    )
    start = time.monotonic()
    assert archive.archive_pending() is True
    assert AuditArchive.objects.count() == 2000
    assert archive.archive_pending() is True
    assert archive.archive_pending() is False
    elapsed = time.monotonic() - start
    assert AuditArchive.objects.count() == 5000
    assert put.call_count == 5
    # Synthetic capacity gate: at least 1000 events/minute, 10x the old cap.
    assert 5000 / elapsed > 1000 / 60
    batches = list(AuditBatch.objects.order_by("sequence"))
    assert batches[0].previous_digest == "0" * 64
    for previous, current in zip(batches, batches[1:]):
        assert current.previous_digest == previous.digest
    print(
        f"Archive simulated throughput: {5000 / elapsed:.0f} events/s, {elapsed:.3f}s, 15 S3 calls"
    )


@pytest.mark.django_db
def test_archive_retry_reuses_pending_bytes_and_lag_alert(org, settings, monkeypatch, caplog):
    settings.AUDIT_BUCKET, settings.AUDIT_RETENTION_DAYS = "synthetic", 30
    fake = Archive()
    monkeypatch.setattr(archive.boto3, "client", lambda *a, **k: fake)
    event = audit(org, None, "test.pending", "test", "1")
    settings.AUDIT_ARCHIVE_MAX_LAG_SECONDS = 900
    later = event.occurred_at + timedelta(seconds=901)
    monkeypatch.setattr(archive.timezone, "now", lambda: later)
    assert archive.archive_lag()["archive_overdue"]
    assert "audit_archive_lag_exceeded" in caplog.text
    fake.corrupt = True
    with pytest.raises(ValueError):
        archive.archive_pending()
    pending = AuditBatch.objects.get()
    original = pending.payload, pending.digest
    assert not AuditArchive.objects.filter(event=event).exists()
    fake.corrupt = False
    archive.archive_pending()
    pending.refresh_from_db()
    assert (pending.payload, pending.digest) == original
    assert pending.archived_at is not None
    assert AuditBatch.objects.count() == 1


@pytest.mark.django_db
def test_fresh_network_correct_password_reaches_only_mfa(client, staff):
    for i in range(10):
        response = client.post(
            "/api/auth/login",
            {"email": staff.email, "password": "wrong"},
            content_type="application/json",
            REMOTE_ADDR=f"198.51.100.{i + 1}",
        )
        assert response.status_code == 401
    response = client.post(
        "/api/auth/login",
        {"email": staff.email, "password": "A-strong-test-only-password!"},
        content_type="application/json",
        REMOTE_ADDR="203.0.113.1",
    )
    assert response.status_code == 200
    assert client.session["pending_user"] == staff.pk
    assert "_auth_user_id" not in client.session


@pytest.mark.django_db
def test_sustained_failures_alert_and_backoff(staff, caplog):
    for _ in range(100):
        delay = record_login_failure(staff)
    assert delay == 1
    for _ in range(10):
        delay = record_login_failure(staff)
    assert delay == 2
    assert "sustained_login_failures" in caplog.text
    assert AuditEvent.objects.filter(action="auth.sustained_failures").count() == 1


@pytest.mark.django_db
def test_idle_polls_do_not_extend_and_activity_cannot_revive(staff_client, settings, monkeypatch):
    now = time.time()
    monkeypatch.setattr("backend.apps.core.middleware.time.time", lambda: now)
    settings.STAFF_IDLE_SECONDS = 900
    session = staff_client.session
    session["staff_started_at"] = now
    session["staff_last_seen"] = now
    session.save()
    now += 899
    assert staff_client.get("/api/auth/session").status_code == 200
    assert staff_client.session["staff_last_seen"] == now - 899
    now += 1
    assert staff_client.post("/api/auth/activity").status_code == 401
    assert "_auth_user_id" not in staff_client.session


@pytest.mark.django_db
def test_activity_renews_idle_but_not_absolute(staff_client, settings, monkeypatch):
    now = time.time()
    monkeypatch.setattr("backend.apps.core.middleware.time.time", lambda: now)
    started = now - 8 * 3600 + 2
    session = staff_client.session
    session["staff_started_at"] = started
    session["staff_last_seen"] = now - 899
    session.save()
    assert staff_client.post("/api/auth/activity").status_code == 200
    assert staff_client.session["staff_last_seen"] == now
    assert staff_client.session["staff_started_at"] == started
    now += 2
    assert staff_client.get("/api/auth/session").status_code == 401


@pytest.mark.django_db
def test_batch_manifest_rebuild_and_chain_rejection(org, settings, monkeypatch, tmp_path):
    from backend.apps.core.archive_verify import rebuild_projection

    settings.AUDIT_BUCKET, settings.AUDIT_RETENTION_DAYS = "synthetic", 30
    settings.AUDIT_ARCHIVE_BATCH_SIZE = 2
    fake = Archive()
    fake.get_object = Mock(wraps=fake.get_object)
    monkeypatch.setattr(archive.boto3, "client", lambda *a, **k: fake)
    for i in range(5):
        audit(org, None, "test.chain", "test", str(i))
    archive.archive_pending()
    entries = [
        dict(
            event_id=str(a.event_id),
            organization=str(org.pk),
            sequence=a.event.sequence,
            object_key=a.object_key,
            version_id=a.version_id,
            digest=a.digest,
            retain_until=a.retain_until.isoformat(),
            batch_id=str(a.batch_id),
            batch_sequence=a.batch.sequence,
            previous_digest=a.batch.previous_digest,
        )
        for a in AuditArchive.objects.select_related("event", "batch").order_by("event__sequence")
    ]
    fake.get_object.reset_mock()
    assert rebuild_projection(fake, "synthetic", entries, tmp_path / "good.sqlite3") == 5
    assert fake.get_object.call_count == 3
    entries[-1]["previous_digest"] = "f" * 64
    with pytest.raises(ValueError, match="broken archive chain"):
        rebuild_projection(fake, "synthetic", entries, tmp_path / "bad.sqlite3")
    assert not (tmp_path / "bad.sqlite3").exists()
