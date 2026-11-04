import json
import uuid
from datetime import timedelta

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import DatabaseError, connection, transaction
from django.test import Client
from django.utils import timezone
from django_otp.oath import TOTP

from backend.apps.core import crypto
from backend.apps.core.accounts import usage_for
from backend.apps.core.audit import csv_safe
from backend.apps.core.mail import payload, process_pending
from backend.apps.core.models import (
    AuditEvent,
    Conversation,
    DeliveryJob,
    Message,
    OTPChallenge,
    StaffUser,
)

pytestmark = pytest.mark.django_db


def post(client, path, body=None, key=None):
    return client.post(
        "/api" + path,
        data=json.dumps(body or {}),
        content_type="application/json",
        HTTP_IDEMPOTENCY_KEY=key or str(uuid.uuid4()),
    )


def compose(client, sender="staff@onesmarter.com", **changes):
    data = {
        "sender": sender,
        "to": ["sara@example.com"],
        "subject": "Document request",
        "mode": "secure_request",
        "body": "",
        "expiry_days": 7,
    }
    data.update(changes)
    if data["mode"] == "ordinary" and "expected_route" not in data:
        preview = post(client, "/routing/preview", data)
        if preview.status_code == 200:
            data["expected_route"] = preview.json()
    return post(client, "/conversations", data)


def recipient_access(staff_client):
    result = compose(staff_client)
    assert result.status_code == 201, result.content
    conversation = Conversation.objects.get(pk=result.json()["id"])
    job = DeliveryJob.objects.get(conversation=conversation)
    token = payload(job)["link"].split("/")[-1]
    client = Client()
    assert post(client, "/recipient/code", {"token": token}).status_code == 200
    code_job = DeliveryJob.objects.filter(conversation=conversation).exclude(pk=job.pk).get()
    code = payload(code_job)["body"].split(" is ")[1][:6]
    assert post(client, "/recipient/verify", {"token": token, "code": code}).status_code == 200
    return client, conversation, token, code


def test_blank_request_stored_encrypted(staff_client):
    response = compose(staff_client)
    assert response.status_code == 201
    obj = Conversation.objects.get(pk=response.json()["id"])
    assert obj.protected
    assert "Document request" not in obj.subject_ciphertext
    assert "Document request" not in payload(DeliveryJob.objects.get(conversation=obj))["body"]


def test_consumed_code_is_not_sent_from_delayed_outbox(staff_client):
    _, conversation, _, _ = recipient_access(staff_client)
    process_pending()
    assert DeliveryJob.objects.filter(
        conversation=conversation,
        error_code="code_superseded",
        state="cancelled",
        payload_ciphertext="",
    ).exists()


def test_last_privilege_manager_cannot_remove_own_authority(admin_client, admin):
    response = post(
        admin_client,
        f"/admin/accounts/{admin.pk}",
        {"action": "permissions", "can_manage_privileges": False, "reason": "Regression test"},
    )
    assert response.status_code == 409
    admin.refresh_from_db()
    assert admin.can_manage_privileges


def test_assigned_staff_can_read_retained_file_after_recipient_access_ends(staff_client):
    recipient, conversation, _, _ = recipient_access(staff_client)
    uploaded = recipient.post(
        "/api/recipient/attachments",
        {"file": SimpleUploadedFile("sara.txt", b"Fictional retained document")},
    )
    ident = uploaded.json()["id"]
    assert post(recipient, "/recipient/conversation", {"attachments": [ident]}).status_code == 201
    assert post(staff_client, f"/conversations/{conversation.pk}/revoke").status_code == 200
    assert recipient.get(f"/api/attachments/{ident}").status_code == 404
    assert staff_client.get(f"/api/attachments/{ident}").content == b"Fictional retained document"


def test_nophi_requires_explicit_permission(staff_client, staff):
    result = compose(
        staff_client,
        mode="ordinary",
        body="Meeting",
        subject="Nophi: notes",
        nophi_override=True,
        nophi_acknowledged=True,
    )
    assert result.status_code == 403
    staff.can_nophi = True
    staff.save()
    result = compose(
        staff_client,
        mode="ordinary",
        body="Meeting",
        subject="Nophi: notes",
        nophi_override=True,
        nophi_acknowledged=True,
    )
    assert result.status_code == 201
    assert not Conversation.objects.get(pk=result.json()["id"]).protected


def test_request_nophi_stays_protected(staff_client):
    result = compose(staff_client, subject="Nophi", to=["colleague@onesmarter.com"])
    assert result.status_code == 201
    assert Conversation.objects.get(pk=result.json()["id"]).protected


def test_invalid_compose_is_rejected(staff_client):
    assert compose(staff_client, mode="ordinary", body="", subject="").status_code == 400
    assert compose(staff_client, to=[]).status_code == 400
    assert compose(staff_client, sender="spoof@onesmarter.com").status_code == 403


def test_compose_idempotency(staff_client):
    data = {"sender": "staff@onesmarter.com", "to": ["sara@example.com"], "mode": "secure_request"}
    first = post(staff_client, "/conversations", data, "same-submit")
    second = post(staff_client, "/conversations", data, "same-submit")
    assert first.status_code == 201 and second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert (
        post(
            staff_client, "/conversations", {**data, "subject": "different"}, "same-submit"
        ).status_code
        == 409
    )
    assert Conversation.objects.count() == 1


def test_recipient_document_roundtrip_and_revoke(staff_client):
    recipient, conversation, _, _ = recipient_access(staff_client)
    file = SimpleUploadedFile(
        "financial.txt", b"Confidential financial test content", content_type="text/plain"
    )
    response = recipient.post("/api/recipient/attachments", {"file": file})
    assert response.status_code == 201, response.content
    ident = response.json()["id"]
    response = post(recipient, "/recipient/conversation", {"attachments": [ident]}, "reply-one")
    assert response.status_code == 201, response.content
    assert (
        post(
            recipient, "/recipient/conversation", {"attachments": [ident]}, "reply-one"
        ).status_code
        == 201
    )
    assert Message.objects.filter(grant__isnull=False).count() == 1
    download = staff_client.get(f"/api/attachments/{ident}")
    assert (
        download.status_code == 200 and download.content == b"Confidential financial test content"
    )
    assert "attachment" in download["Content-Disposition"]
    assert post(staff_client, f"/conversations/{conversation.pk}/revoke").status_code == 200
    assert recipient.get("/api/recipient/conversation").status_code == 404
    assert recipient.get(f"/api/attachments/{ident}").status_code == 404


def test_code_once_and_fixed_destination(staff_client):
    recipient, conversation, token, code = recipient_access(staff_client)
    assert post(Client(), "/recipient/verify", {"token": token, "code": code}).status_code == 400
    landing = post(Client(), "/recipient/landing", {"token": token})
    assert landing.status_code == 200 and landing.json()["recipient"] == "s***@example.com"
    assert all(payload(j)["to"] == "sara@example.com" for j in conversation.delivery_jobs.all())


def test_wrong_code_attempts_persist(staff_client):
    compose(staff_client)
    invitation = DeliveryJob.objects.get()
    token = payload(invitation)["link"].split("/")[-1]
    client = Client()
    assert post(client, "/recipient/code", {"token": token}).status_code == 200
    for _ in range(5):
        response = post(client, "/recipient/verify", {"token": token, "code": "------"})
        assert response.status_code == 400
    # Invalid format is rejected before verification; valid-looking wrong attempts are counted.
    # Creation timestamps can tie: select the OTP job, never the invitation.
    code = payload(DeliveryJob.objects.exclude(pk=invitation.pk).get())["body"].split(" is ")[1][:6]
    wrong = "111111" if code != "111111" else "222222"
    for _ in range(5):
        assert post(client, "/recipient/verify", {"token": token, "code": wrong}).status_code == 400
    assert OTPChallenge.objects.get().attempts == 5
    assert post(client, "/recipient/verify", {"token": token, "code": code}).status_code == 400


def test_expired_code_denied(staff_client):
    compose(staff_client)
    token = payload(DeliveryJob.objects.first())["link"].split("/")[-1]
    client = Client()
    post(client, "/recipient/code", {"token": token})
    OTPChallenge.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    assert post(client, "/recipient/verify", {"token": token, "code": "123456"}).status_code == 400


def test_admin_cannot_read_other_staff_content(staff_client, admin_client):
    ident = compose(staff_client).json()["id"]
    assert admin_client.get(f"/api/conversations/{ident}").status_code == 404


def test_staff_cannot_access_admin(staff_client):
    assert staff_client.get("/api/admin/accounts").status_code == 403
    assert staff_client.get("/api/admin/audit-events").status_code == 403


def test_account_invite_activation(admin_client):
    response = post(
        admin_client, "/admin/accounts", {"name": "New Staff", "email": "new@onesmarter.com"}
    )
    assert response.status_code == 201, response.content
    user = StaffUser.objects.get(pk=response.json()["id"])
    assert user.status == "invited" and not user.has_usable_password() and not user.can_nophi
    token = payload(DeliveryJob.objects.latest("created_at"))["link"].split("/")[-1]
    client = Client()
    assert (
        post(
            client, "/auth/activate", {"token": token, "password": "Long-New-Staff-Password-23!"}
        ).status_code
        == 200
    )
    user.refresh_from_db()
    assert user.last_login is None and not user.mfa_confirmed
    assert (
        post(
            Client(), "/auth/activate", {"token": token, "password": "Long-New-Staff-Password-23!"}
        ).status_code
        == 400
    )


def test_suspension_revokes_session(admin_client, staff_client, staff):
    response = post(
        admin_client,
        f"/admin/accounts/{staff.pk}",
        {"action": "suspend", "reason": "Test offboarding"},
    )
    assert response.status_code == 200, response.content
    assert staff_client.get("/api/conversations").status_code == 401


def test_last_admin_is_protected(admin_client, admin):
    assert (
        post(
            admin_client, f"/admin/accounts/{admin.pk}", {"action": "deactivate", "reason": "Test"}
        ).status_code
        == 409
    )


def test_ciphertext_and_context_tampering_rejected(org):
    context = crypto.context(org.pk, "message", "1")
    encrypted = crypto.encrypt(b"document", context)
    assert crypto.decrypt(encrypted, context) == b"document"
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(encrypted, crypto.context(org.pk, "message", "2"))
    data = json.loads(encrypted)
    content = bytearray(crypto.unb64(data["data"]))
    content[0] ^= 1
    data["data"] = crypto.b64(bytes(content))
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(json.dumps(data), context)


def test_audit_is_immutable_at_database(org):
    event = AuditEvent.objects.create(
        organization=org,
        actor_id="1",
        actor_label="Test",
        actor_role="staff",
        action="test",
        target_type="test",
        target_id="1",
    )
    with pytest.raises(ValueError):
        event.delete()
    with pytest.raises(ValueError):
        AuditEvent.objects.filter(pk=event.pk).update(action="changed")
    with pytest.raises(DatabaseError), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE core_auditevent SET action = %s WHERE id = %s",
                ["changed", event.pk.hex if connection.vendor == "sqlite" else event.pk],
            )
    event.refresh_from_db()
    assert event.action == "test"


def test_audit_export_and_snapshot(admin_client, org):
    AuditEvent.objects.create(
        organization=org,
        actor_id="1",
        actor_label="=SUM(1,2)",
        actor_role="staff",
        action="test",
        target_type="account",
        target_id="1",
    )
    page = admin_client.get("/api/admin/audit-events").json()
    again = admin_client.get("/api/admin/audit-events", {"snapshot": page["snapshot"]}).json()
    assert [e["id"] for e in page["results"]] == [e["id"] for e in again["results"]]
    response = post(admin_client, "/admin/audit-exports", {"snapshot": page["snapshot"]})
    assert response.status_code == 201
    exported = admin_client.get(response.json()["download_url"])
    assert exported.status_code == 200 and b"'=SUM" in exported.content
    assert csv_safe(" \t=1+1").startswith("'")


def test_invalid_sort_rejected(admin_client):
    assert admin_client.get("/api/admin/accounts?sort=password").status_code == 400


def test_mfa_login_updates_timestamp_only_after_factor(org):
    user = StaffUser.objects.create_user(
        username="mfa@onesmarter.com",
        email="mfa@onesmarter.com",
        password="Long-MFA-Test-Password-23!",
        organization=org,
        display_name="MFA",
        status="active",
    )
    client = Client()
    assert (
        post(
            client, "/auth/login", {"email": user.email, "password": "Long-MFA-Test-Password-23!"}
        ).status_code
        == 200
    )
    enrolled = post(client, "/auth/enroll")
    assert enrolled.status_code == 200
    user.refresh_from_db()
    assert user.last_login is None
    secret = crypto.decrypt(user.mfa_secret, crypto.context(user.organization_id, "mfa", user.pk))
    response = post(client, "/auth/verify", {"token": f"{TOTP(secret).token():06d}"})
    assert response.status_code == 200, response.content
    assert len(response.json()["recovery_codes"]) == 8
    user.refresh_from_db()
    assert user.last_login is not None and user.mfa_confirmed


def test_csrf_protects_anonymous_login(org):
    client = Client(enforce_csrf_checks=True)
    response = post(client, "/auth/login", {"email": "nobody@onesmarter.com", "password": "no"})
    assert response.status_code == 403


def test_notification_worker_and_usage_deduplicate(staff_client, staff):
    compose(staff_client)
    process_pending()
    process_pending()
    assert DeliveryJob.objects.get().attempts == 1
    assert DeliveryJob.objects.get().state == "development_delivered"
    assert usage_for([staff], staff.organization)[staff.pk]["secure_requests"] == 1


def test_mismatched_file_type_rejected(staff_client):
    assert (
        staff_client.post(
            "/api/attachments", {"file": SimpleUploadedFile("fake.pdf", b"not a pdf")}
        ).status_code
        == 400
    )
