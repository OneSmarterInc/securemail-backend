from unittest.mock import Mock

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from backend.apps.core import document_service, storage
from backend.apps.core.mail import process_job
from backend.apps.core.models import Attachment, Conversation, DeliveryJob, Message
from backend.keyservice.protocol import SUITE
from backend.tests.test_flows import compose, post, recipient_access

pytestmark = pytest.mark.django_db
READY = {"sealed": False, "suite": SUITE}


@pytest.mark.parametrize(
    "status",
    [
        None,
        {},
        {"sealed": True, "suite": SUITE},
        {"sealed": 0, "suite": SUITE},
        {"sealed": False, "suite": "unknown"},
        {**READY, "audit_integrity": "failed"},
    ],
)
def test_disabled_service_blocks_compose_without_writes(staff_client, monkeypatch, status):
    monkeypatch.setattr(document_service, "read_status", lambda: status)
    response = compose(staff_client)
    assert response.status_code == 503
    assert response.json()["error"] == {
        "code": "service_disabled",
        "message": "Service is disabled.",
    }
    assert not Conversation.objects.exists()
    assert not DeliveryJob.objects.exists()


def test_unreachable_service_fails_closed(staff_client, monkeypatch):
    monkeypatch.setattr(
        document_service, "read_status", Mock(side_effect=ValueError("unreachable"))
    )
    assert compose(staff_client).status_code == 503
    response = staff_client.get("/api/document-service")
    assert response.json()["ready"] is False
    assert response.json()["message"] == "Service is disabled."
    assert response["Cache-Control"] == "no-store"


def test_seal_during_compose_rolls_back(staff_client, monkeypatch):
    monkeypatch.setattr(
        document_service, "read_status", Mock(side_effect=[READY, {"sealed": True}])
    )
    assert compose(staff_client).status_code == 503
    assert not Conversation.objects.exists()
    assert not Message.objects.exists()
    assert not DeliveryJob.objects.exists()


def test_disabled_uploads_and_replies_for_staff_and_recipient(staff_client, monkeypatch):
    visitor, conversation, _, _ = recipient_access(staff_client)
    initial_messages = Message.objects.count()
    monkeypatch.setattr(document_service, "read_status", lambda: {"sealed": True})
    scan = Mock(side_effect=AssertionError("Do not process documents while sealed"))
    monkeypatch.setattr(storage, "validate_file", scan)
    for client, route in (
        (staff_client, "/api/attachments"),
        (visitor, "/api/recipient/attachments"),
    ):
        response = client.post(route, {"file": SimpleUploadedFile("test.txt", b"Synthetic")})
        assert response.status_code == 503
    assert (
        post(
            staff_client, f"/conversations/{conversation.pk}/messages", {"body": "test"}
        ).status_code
        == 503
    )
    assert post(visitor, "/recipient/conversation", {"body": "test"}).status_code == 503
    assert Message.objects.count() == initial_messages
    assert not Attachment.objects.exists()
    scan.assert_not_called()


def test_queued_delivery_waits_and_resumes(staff_client, monkeypatch):
    assert compose(staff_client).status_code == 201
    job = DeliveryJob.objects.get()
    monkeypatch.setattr(document_service, "read_status", lambda: {"sealed": True})
    process_job(job.pk)
    job.refresh_from_db()
    assert job.state == "queued" and job.attempts == 0
    assert job.error_code == "service_disabled"
    monkeypatch.setattr(document_service, "read_status", lambda: READY)
    DeliveryJob.objects.filter(pk=job.pk).update(next_attempt=timezone.now())
    process_job(job.pk)
    job.refresh_from_db()
    assert job.state == "development_delivered"


def test_sealed_admission_defers_without_sending(
    staff_client, monkeypatch, settings, sender_profile
):
    from backend.apps.core import mail

    assert compose(staff_client).status_code == 201
    job = DeliveryJob.objects.get()
    monkeypatch.setattr(document_service, "read_status", Mock(return_value={"sealed": True}))
    transport = Mock()
    monkeypatch.setattr(mail, "EmailMultiAlternatives", transport)
    settings.MAIL_PROVIDER = "smtp"
    settings.EMAIL_HOST_USER = "synthetic@example.test"
    settings.EMAIL_HOST_PASSWORD = "synthetic-test-only"
    process_job(job.pk)
    transport.return_value.send.assert_not_called()
    job.refresh_from_db()
    assert job.state == "queued" and job.error_code == "service_disabled"
    assert document_service.read_status.call_count == 1


def test_local_default_roundtrip_without_remote_status(staff_client, settings, monkeypatch):
    from backend.apps.core.models import WrappingKeyVersion

    settings.KEY_PROTECTOR = "local-development"
    settings.SYNTHETIC_MODE = True
    settings.KEY_STATUS_URL = ""
    settings.KEY_SERVICE_URL = ""
    remote = Mock(side_effect=AssertionError("Local crypto must not contact a remote service"))
    monkeypatch.setattr(document_service, "pooled_client", remote)
    assert document_service.ready()
    visitor, conversation, _, _ = recipient_access(staff_client)
    upload = visitor.post(
        "/api/recipient/attachments",
        {
            "file": SimpleUploadedFile(
                "preview.txt", b"synthetic round trip", content_type="text/plain"
            )
        },
    )
    assert upload.status_code == 201, upload.content
    file_id = upload.json()["id"]
    reply = post(visitor, "/recipient/conversation", {"body": "Uploaded", "attachments": [file_id]})
    assert reply.status_code == 201, reply.content
    assert staff_client.get(f"/api/attachments/{file_id}").content == b"synthetic round trip"
    assert WrappingKeyVersion.objects.filter(state="active").exists()
    for job in DeliveryJob.objects.filter(conversation=conversation):
        process_job(job.pk)
    # The OTP was consumed before the worker ran and is correctly cancelled.
    assert DeliveryJob.objects.filter(state="development_delivered").count() == 2
    assert not DeliveryJob.objects.exclude(
        state__in=["development_delivered", "cancelled"]
    ).exists()
    remote.assert_not_called()


@pytest.mark.parametrize("root_state", ["missing", "malformed", "wrong_length", "changed"])
def test_local_readiness_checks_actual_root_file(staff_client, settings, root_state):
    import base64
    import secrets

    from backend.apps.core import crypto

    settings.KEY_PROTECTOR = "local-development"
    assert document_service.ready()
    if root_state == "missing":
        settings.LOCAL_KEY_FILE.unlink()
    else:
        contents = {
            "malformed": "not-base64!",
            "wrong_length": base64.b64encode(b"short").decode(),
            "changed": base64.b64encode(secrets.token_bytes(32)).decode(),
        }
        settings.LOCAL_KEY_FILE.write_text(contents[root_state])
    assert not document_service.ready()
    assert compose(staff_client).status_code == 503
    crypto._local_key.cache_clear()


def test_local_readiness_checks_active_key_material(staff_client):
    from backend.apps.core.models import WrappingKeyVersion

    assert compose(staff_client).status_code == 201
    WrappingKeyVersion.objects.filter(state="active").update(private_ciphertext="{}")
    assert not document_service.ready()


def test_local_protector_never_ready_outside_synthetic(settings):
    settings.KEY_PROTECTOR = "local-development"
    settings.SYNTHETIC_MODE = False
    assert not document_service.ready()


def test_remote_protector_does_not_fall_back_to_local_keys(settings, monkeypatch):
    settings.KEY_PROTECTOR = "key-service"
    remote = Mock()
    remote.return_value.call.return_value = {"sealed": True, "suite": SUITE}
    monkeypatch.setattr(document_service, "pooled_client", remote)
    assert not document_service.ready()
    remote.return_value.call.assert_called_once_with("status")
