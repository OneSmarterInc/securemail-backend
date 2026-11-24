import json
import re

import pytest
from django.core import mail as capture
from django.test import Client

from backend.apps.core import mail
from backend.apps.core.models import DeliveryJob
from backend.tests.test_api_keys import invoke, issue

pytestmark = pytest.mark.django_db


def template():
    return {
        "name": "XYZ",
        "html": "<h1>A message from XYZ</h1>",
        "text": "XYZ secure notification",
        "otp_html": "<h1>Verify with XYZ</h1>",
        "otp_css": "color:#123456",
        "otp_text": "XYZ verification",
        "theme": {"name": "XYZ Software", "primary": "#123456", "background": "#f8f8f8"},
    }


def post(client, path, data):
    return client.post(
        "/recipient-api/recipient/" + path, json.dumps(data), content_type="application/json"
    )


def test_notification_otp_and_portal_share_bound_presentation(admin_client, admin, sender_profile):
    token = issue(admin_client)["secret"]
    preview = invoke(token, "/api/v1/templates/preview", "post", template())
    assert preview.status_code == 200, preview.content
    assert "000000" in preview.json()["otp_html"]
    assert not DeliveryJob.objects.exists()
    saved = invoke(
        token, "/api/v1/templates", "post", template(), HTTP_IDEMPOTENCY_KEY="template-v1"
    )
    assert saved.status_code == 201, saved.content
    data = {
        "to": "receiver@example.test",
        "sender": admin.email,
        "subject": "PRIVATE SUBJECT",
        "body": "PRIVATE BODY",
        "template_id": saved.json()["id"],
    }
    created = invoke(token, "/api/v1/messages", "post", data, HTTP_IDEMPOTENCY_KEY="message-v1")
    assert created.status_code == 201, created.content
    invitation = DeliveryJob.objects.get()
    contents = mail.payload(invitation)
    invitation_token = contents["link"].split("/invite/")[1]
    mail.process_job(invitation.pk)
    assert "A message from XYZ" in capture.outbox[-1].alternatives[0].content
    assert "PRIVATE" not in capture.outbox[-1].body + capture.outbox[-1].alternatives[0].content
    visitor = Client()
    landing = post(visitor, "landing", {"token": invitation_token})
    assert landing.json()["theme"]["name"] == "XYZ Software"
    assert landing.json()["auto_send_code"] is True
    assert visitor.get("/recipient-api/recipient/conversation").status_code == 401
    assert (
        post(
            visitor, "code", {"token": invitation_token, "email": "attacker@example.test"}
        ).status_code
        == 200
    )
    otp = DeliveryJob.objects.exclude(pk=invitation.pk).get()
    contents = mail.payload(otp)
    assert contents["to"] == "receiver@example.test"
    code = re.search(r"code is (\d{6})", contents["body"])[1]
    mail.process_job(otp.pk)
    assert "Verify with XYZ" in capture.outbox[-1].alternatives[0].content
    assert code in capture.outbox[-1].alternatives[0].content
    assert "XYZ verification" in capture.outbox[-1].body
    assert post(visitor, "verify", {"token": invitation_token, "code": code}).status_code == 200
    detail = visitor.get("/recipient-api/recipient/conversation")
    assert detail.status_code == 200, detail.content
    assert detail.json()["theme"]["primary"] == "#123456"
    assert detail.json()["messages"][0]["body"] == "PRIVATE BODY"
    assert post(visitor, "verify", {"token": invitation_token, "code": code}).status_code == 400


@pytest.mark.parametrize(
    "change", ["script", "logo", "contrast", "background", "otp_missing", "url"]
)
def test_invalid_presentation_rejected(admin_client, change):
    data = template()
    if change == "script":
        data["otp_html"] = "<script>alert(1)</script>"
    elif change == "logo":
        data["theme"]["logo_png"] = "PHN2Zz4="
    elif change == "contrast":
        data["theme"]["primary"] = "#ffffff"
    elif change == "background":
        data["theme"]["background"] = "#000000"
    elif change == "otp_missing":
        del data["otp_text"]
    else:
        data["theme"]["logo_url"] = "https://tracker.example.test/"
    assert (
        invoke(issue(admin_client)["secret"], "/api/v1/templates/preview", "post", data).status_code
        == 400
    )


def test_selfpay_profile_requires_owner_and_retains_templates(admin_client, admin, settings):
    data = {
        "name": "SelfPay new triggers",
        "scopes": ["messages:write"],
        "notification_profile": "selfpay",
    }
    denied = admin_client.post(
        "/api/admin/api-keys", json.dumps(data), content_type="application/json"
    )
    assert denied.status_code == 403
    settings.SECURE_MAIL_INTEGRATIONS = {"selfpay": {"owner_id": admin.pk, "enabled": True}}
    issued = admin_client.post(
        "/api/admin/api-keys", json.dumps(data), content_type="application/json"
    )
    assert issued.status_code == 201, issued.content
    body = {
        "to": "clinic@example.test",
        "sender": admin.email,
        "subject": "Private",
        "body": "Private body",
    }
    sent = invoke(
        issued.json()["secret"],
        "/api/v1/messages",
        "post",
        body,
        HTTP_IDEMPOTENCY_KEY="selfpay-new",
    )
    assert sent.status_code == 201, sent.content
    from backend.apps.core.portal import notification_source

    job = DeliveryJob.objects.get()
    assert notification_source(mail.payload(job), job) == "selfpay"
    body["template_id"] = "00000000-0000-0000-0000-000000000001"
    assert (
        invoke(
            issued.json()["secret"],
            "/api/v1/messages",
            "post",
            body,
            HTTP_IDEMPOTENCY_KEY="custom-denied",
        ).status_code
        == 400
    )


def test_png_logo_validation_and_template_key_isolation(admin_client):
    import base64
    import struct
    import zlib

    def chunk(kind, data):
        return (
            struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        )

    raw = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\x12\x34\x56"))
        + chunk(b"IEND", b"")
    )
    data = template()
    data["theme"]["logo_png"] = base64.b64encode(raw).decode()
    token = issue(admin_client)["secret"]
    saved = invoke(token, "/api/v1/templates", "post", data, HTTP_IDEMPOTENCY_KEY="logo-template")
    assert saved.status_code == 201, saved.content
    other = issue(admin_client)["secret"]
    assert invoke(other, "/api/v1/templates/" + saved.json()["id"]).status_code == 404
    data["theme"]["logo_png"] = base64.b64encode(raw[:-1] + b"\x00").decode()
    assert invoke(token, "/api/v1/templates/preview", "post", data).status_code == 400


def test_otp_for_one_invitation_cannot_open_another(admin_client, admin):
    token = issue(admin_client)["secret"]
    invitations = []
    for index in (1, 2):
        data = {
            "to": f"recipient{index}@example.test",
            "sender": admin.email,
            "subject": "Private",
            "body": f"Private {index}",
        }
        assert (
            invoke(
                token, "/api/v1/messages", "post", data, HTTP_IDEMPOTENCY_KEY=f"recipient-{index}"
            ).status_code
            == 201
        )
        job = (
            DeliveryJob.objects.filter(conversation__apimessage__isnull=False)
            .order_by("-created_at", "-pk")
            .first()
        )
        invitations.append(mail.payload(job)["link"].split("/invite/")[1])
    visitor = Client()
    for invitation in invitations:
        assert post(visitor, "code", {"token": invitation}).status_code == 200
    job = next(
        j
        for j in DeliveryJob.objects.all()
        if mail.payload(j).get("challenge_id")
        and mail.payload(j)["to"] == "recipient1@example.test"
    )
    code = re.search(r"code is (\d{6})", mail.payload(job)["body"])[1]
    assert post(visitor, "verify", {"token": invitations[1], "code": code}).status_code == 400
    assert visitor.get("/recipient-api/recipient/conversation").status_code == 401
    assert post(visitor, "verify", {"token": invitations[0], "code": code}).status_code == 200
    assert (
        visitor.get("/recipient-api/recipient/conversation").json()["messages"][0]["body"]
        == "Private 1"
    )


@pytest.mark.parametrize("reply", [True, False])
def test_recipient_reply_policy_enforced_after_otp(admin_client, admin, reply):
    from django.core.files.uploadedfile import SimpleUploadedFile

    from backend.apps.core.models import Attachment, Message

    token = issue(admin_client)["secret"]
    data = {
        "to": "recipient@example.test",
        "sender": admin.email,
        "subject": "Notice",
        "body": "Protected notice",
        "reply": reply,
    }
    created = invoke(token, "/api/v1/messages", "post", data, HTTP_IDEMPOTENCY_KEY="reply-policy")
    assert created.status_code == 201, created.content
    assert invoke(token, "/api/v1/messages/" + created.json()["id"]).json()["reply"] is reply
    invitation = mail.payload(DeliveryJob.objects.get())["link"].split("/invite/")[1]
    visitor = Client()
    assert post(visitor, "code", {"token": invitation}).status_code == 200
    contents = next(
        mail.payload(j) for j in DeliveryJob.objects.all() if mail.payload(j).get("challenge_id")
    )
    code = re.search(r"code is (\d{6})", contents["body"])[1]
    assert post(visitor, "verify", {"token": invitation, "code": code}).status_code == 200
    assert visitor.get("/recipient-api/recipient/conversation").json()["can_reply"] is reply
    result = visitor.post(
        "/recipient-api/recipient/conversation",
        json.dumps({"body": "My reply"}),
        content_type="application/json",
        HTTP_IDEMPOTENCY_KEY="recipient-reply",
    )
    assert result.status_code == (201 if reply else 403), result.content
    uploaded = visitor.post(
        "/recipient-api/recipient/attachments",
        {"file": SimpleUploadedFile("test.txt", b"synthetic")},
    )
    assert uploaded.status_code == (201 if reply else 403), uploaded.content
    if not reply:
        assert result.json()["error"]["code"] == "replies_disabled"
        assert Message.objects.count() == 1
        assert not Attachment.objects.exists()


@pytest.mark.parametrize("reply", ["false", "true", 0, 1, None])
def test_reply_flag_requires_json_boolean(admin_client, admin, reply):
    token = issue(admin_client)["secret"]
    result = invoke(
        token,
        "/api/v1/messages",
        "post",
        {
            "to": "recipient@example.test",
            "sender": admin.email,
            "subject": "Notice",
            "body": "Notice",
            "reply": reply,
        },
        HTTP_IDEMPOTENCY_KEY="invalid-reply",
    )
    assert result.status_code == 400
    assert not DeliveryJob.objects.exists()
