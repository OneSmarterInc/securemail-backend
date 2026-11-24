import json
import time
from datetime import timedelta

import pytest
from django.test import Client
from django.utils import timezone

from backend.apps.core.models import ApiKey, ApiMessage, Conversation, DeliveryJob, Message

pytestmark = pytest.mark.django_db


def issue(client, scopes=None):
    response = client.post(
        "/api/admin/api-keys",
        json.dumps(
            {
                "name": "Synthetic integration",
                "scopes": scopes or ["status:read", "messages:read", "messages:write"],
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 201, response.content
    return response.json()


def invoke(token, path="/api/v1/status", method="get", data=None, **headers):
    return getattr(Client(enforce_csrf_checks=True), method)(
        path,
        **(
            {"data": json.dumps(data), "content_type": "application/json"}
            if data is not None
            else {}
        ),
        HTTP_AUTHORIZATION="Bearer " + token,
        **headers,
    )


def test_issue_hash_once_scope_revoke_and_expiry(admin_client):
    created = issue(admin_client)
    token = created["secret"]
    stored = ApiKey.objects.get()
    assert token not in stored.digest and len(stored.digest) == 64
    assert token not in admin_client.get("/api/admin/api-keys").content.decode()
    assert invoke(token).status_code == 200
    assert invoke(token + "wrong").status_code == 401
    assert Client().get("/api/v1/status").status_code == 401
    assert Client().get("/api/v1/status", {"api_key": token}).status_code == 401
    assert admin_client.post(f"/api/admin/api-keys/{stored.pk}/revoke").status_code == 200
    assert invoke(token).status_code == 401
    created = issue(admin_client, ["status:read"])
    assert invoke(created["secret"], "/api/v1/messages").status_code == 403
    ApiKey.objects.filter(pk=created["id"]).update(expires_at=timezone.now() - timedelta(seconds=1))
    assert invoke(created["secret"]).status_code == 401


def test_keys_require_admin_privilege_csrf_and_fresh_mfa(admin_client, staff_client, admin):
    assert staff_client.get("/api/admin/api-keys").status_code == 403
    session = admin_client.session
    session["mfa_at"] = time.time() - 601
    session.save()
    assert (
        admin_client.post("/api/admin/api-keys", {}, content_type="application/json").status_code
        == 403
    )
    strict = Client(enforce_csrf_checks=True)
    strict.force_login(admin)
    assert (
        strict.post("/api/admin/api-keys", {}, content_type="application/json").status_code == 403
    )


def test_api_send_is_protected_idempotent_and_isolated(admin_client, admin):
    token = issue(admin_client)["secret"]
    data = {
        "to": "recipient@example.test",
        "sender": admin.email,
        "subject": "Synthetic subject",
        "body": "Synthetic private body",
    }
    response = invoke(
        token, "/api/v1/messages", "post", data, HTTP_IDEMPOTENCY_KEY="test-request-1"
    )
    assert response.status_code == 201, response.content
    ident = response.json()["id"]
    assert Conversation.objects.get().protected
    assert "Synthetic" not in Message.objects.get().body_ciphertext
    assert DeliveryJob.objects.count() == 1
    assert (
        invoke(
            token, "/api/v1/messages", "post", data, HTTP_IDEMPOTENCY_KEY="test-request-1"
        ).status_code
        == 200
    )
    assert DeliveryJob.objects.count() == 1
    assert (
        invoke(
            token,
            "/api/v1/messages",
            "post",
            {**data, "body": "changed"},
            HTTP_IDEMPOTENCY_KEY="test-request-1",
        ).status_code
        == 409
    )
    result = invoke(token, "/api/v1/messages/" + ident)
    assert result.status_code == 200, result.content
    assert result.json()["subject"] == data["subject"]
    other = issue(admin_client)["secret"]
    assert invoke(other, "/api/v1/messages/" + ident).status_code == 404
    assert invoke(other, "/api/v1/messages").json()["results"] == []
    assert invoke(token, "/api/admin/accounts").status_code == 401
    assert ApiMessage.objects.count() == 1


def test_disabled_owner_and_sealed_service_deny(admin_client, admin, monkeypatch):
    token = issue(admin_client)["secret"]
    monkeypatch.setattr("backend.apps.core.document_service.ready", lambda: False)
    assert invoke(token).json()["ready"] is False
    assert invoke(token, "/api/v1/messages").status_code == 503
    admin.is_active = False
    admin.save()
    assert invoke(token).status_code == 401


def test_public_api_https_and_rate_limit(admin_client, settings, monkeypatch):
    token = issue(admin_client)["secret"]
    now = timezone.now()
    monkeypatch.setattr(timezone, "now", lambda: now)
    settings.SYNTHETIC_MODE = False
    assert invoke(token).status_code == 403
    settings.SYNTHETIC_MODE = True
    for _ in range(60):
        assert invoke(token).status_code == 200
    assert invoke(token).status_code == 429


def test_admin_filters_combine_before_pagination_and_exclude_other_org(admin_client):
    from backend.apps.core.models import Organization

    active = issue(admin_client, ["status:read", "messages:read", "messages:write"])
    expired = issue(admin_client, ["messages:read"])
    revoked = issue(admin_client, ["messages:write"])
    foreign = issue(admin_client)
    ApiKey.objects.filter(pk=active["id"]).update(name="Clinic production")
    ApiKey.objects.filter(pk=expired["id"]).update(expires_at=timezone.now() - timedelta(days=1))
    ApiKey.objects.filter(pk=revoked["id"]).update(revoked_at=timezone.now())
    other = Organization.objects.create(name="Other", domain="other.test")
    ApiKey.objects.filter(pk=foreign["id"]).update(organization=other)

    def listed(**filters):
        response = admin_client.get("/api/admin/api-keys", filters)
        assert response.status_code == 200
        return {row["id"] for row in response.json()["results"]}

    assert listed() == {active["id"], expired["id"], revoked["id"]}
    assert listed(status="active", scope="messages:write", q="clinic") == {active["id"]}
    assert listed(status="expired", scope="messages:read") == {expired["id"]}
    assert listed(status="revoked") == {revoked["id"]}
    assert listed(scope="status:read") == {active["id"]}
    assert listed(status="active", q="missing") == set()
    assert admin_client.get("/api/admin/api-keys", {"status": "bad"}).status_code == 400
    assert admin_client.get("/api/admin/api-keys", {"scope": "admin"}).status_code == 400
    assert admin_client.get("/api/admin/api-keys/guide").status_code == 200


def test_custom_template_preview_storage_isolation_and_delivery(
    admin_client, admin, settings, sender_profile
):
    from django.core import mail

    from backend.apps.core.mail import process_job
    from backend.apps.core.models import ApiEmailTemplate

    token = issue(admin_client)["secret"]
    template = {
        "name": "Clinic",
        "html": '<h1 style="color:#087e83">Clinic update</h1><p>Please review your secure message.</p>',
        "css": "background-color:#ffffff;font-family:Arial;padding:20px",
        "text": "Clinic update: please review your secure message.",
    }
    preview = invoke(token, "/api/v1/templates/preview", "post", template)
    assert preview.status_code == 200, preview.content
    assert "example.invalid/preview" in preview.json()["html"]
    assert DeliveryJob.objects.count() == 0
    created = invoke(
        token, "/api/v1/templates", "post", template, HTTP_IDEMPOTENCY_KEY="template-1"
    )
    assert created.status_code == 201, created.content
    ident = created.json()["id"]
    assert "Clinic update" not in ApiEmailTemplate.objects.get().content_ciphertext
    assert (
        invoke(
            token, "/api/v1/templates", "post", template, HTTP_IDEMPOTENCY_KEY="template-1"
        ).status_code
        == 200
    )
    assert ApiEmailTemplate.objects.count() == 1
    assert invoke(token, f"/api/v1/templates/{ident}").json()["html"] == template["html"]
    other = issue(admin_client)["secret"]
    assert invoke(other, f"/api/v1/templates/{ident}").status_code == 404
    data = {
        "to": "recipient@example.test",
        "sender": admin.email,
        "subject": "Private subject",
        "body": "Private body",
        "template_id": ident,
    }
    assert (
        invoke(other, "/api/v1/messages", "post", data, HTTP_IDEMPOTENCY_KEY="send-1").status_code
        == 404
    )
    sent = invoke(token, "/api/v1/messages", "post", data, HTTP_IDEMPOTENCY_KEY="send-1")
    assert sent.status_code == 201, sent.content
    settings.MAIL_PROVIDER = "smtp"
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
    settings.EMAIL_HOST_USER = "test-only"
    settings.EMAIL_HOST_PASSWORD = "test-only"
    process_job(DeliveryJob.objects.get().pk)
    outcome = DeliveryJob.objects.get()
    assert outcome.state == "provider_accepted", (outcome.state, outcome.error_code)
    delivered = mail.outbox[0]
    assert template["text"] in delivered.body
    assert "Clinic update" in delivered.alternatives[0].content
    assert "Read secure message" in delivered.alternatives[0].content
    assert "Private body" not in delivered.alternatives[0].content
    assert "Private subject" not in delivered.subject


@pytest.mark.parametrize(
    "markup,css",
    [
        ("<script>alert(1)</script>", ""),
        ('<p onclick="alert(1)">hello</p>', ""),
        ('<a href="https://evil.test">go</a>', ""),
        ('<img src="https://evil.test/track">', ""),
        ("<p>hello</p>", "background-image:url(https://evil.test)"),
        ('<p style="color:expression(alert(1))">hello</p>', ""),
        ("<style>p {color:red}</style>", ""),
        ("<p>unclosed", ""),
        ("<p>hello</p>", "position:fixed"),
    ],
)
def test_template_rejects_unsafe_markup(admin_client, markup, css):
    token = issue(admin_client)["secret"]
    result = invoke(
        token,
        "/api/v1/templates/preview",
        "post",
        {"name": "Test", "html": markup, "css": css, "text": "Test"},
    )
    assert result.status_code == 400, result.content
