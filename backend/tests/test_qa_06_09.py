import time

import pytest

from backend.apps.core.models import AuditEvent
from backend.apps.core.services import record_login_failure


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
