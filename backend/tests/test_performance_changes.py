from unittest.mock import Mock

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import transaction

from backend.apps.core import conversations, crypto
from backend.apps.core.models import Conversation, DeliveryJob, Message
from backend.apps.core.services import queue_mail
from backend.tests.test_flows import compose, post
from backend.tests.test_shared_mail import access

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("count", [100, 1000, 5000])
def test_first_page_decryption_is_bounded(staff_client, monkeypatch, count):
    conversation = Conversation.objects.get(pk=compose(staff_client).json()["id"])
    Message.objects.bulk_create(
        [
            Message(
                conversation=conversation, staff=conversation.owner, body_ciphertext="synthetic"
            )
            for _ in range(count)
        ]
    )
    decrypt = Mock(side_effect=lambda values: [b"synthetic"] * len(values))
    monkeypatch.setattr(crypto, "decrypt_many", decrypt)
    response = staff_client.get(f"/api/conversations/{conversation.pk}")
    assert response.status_code == 200
    assert len(response.json()["messages"]) == 50
    assert len(decrypt.call_args.args[0]) == 51
    cursor = response.json()["next_messages_cursor"]
    second = staff_client.get(f"/api/conversations/{conversation.pk}", {"before": cursor})
    assert not {m["id"] for m in response.json()["messages"]} & {
        m["id"] for m in second.json()["messages"]
    }
    assert (
        staff_client.get(
            f"/api/conversations/{conversation.pk}", {"before": cursor + "invalid"}
        ).status_code
        == 400
    )


def test_recipient_archive_retains_documents_outside_latest_page(staff_client):
    upload = staff_client.post(
        "/api/attachments", {"file": SimpleUploadedFile("old.txt", b"fictional old document")}
    )
    assert upload.status_code == 201
    conversation = Conversation.objects.get(
        pk=compose(staff_client, attachments=[upload.json()["id"]]).json()["id"]
    )
    client = access("sara@example.com")
    for _ in range(51):
        message = Message(conversation=conversation, staff=conversation.owner)
        message.body_ciphertext = crypto.encrypt(b"newer", conversations.message_context(message))
        message.save()
    latest = client.get("/api/recipient/conversation").json()
    assert len(latest["messages"]) == 50
    assert not any(m["attachments"] for m in latest["messages"])
    docs = client.get("/api/recipient/documents").json()
    assert docs["count"] == 1 and docs["results"][0]["name"] == "old.txt"
    # The staff cursor cannot be used through a recipient grant.
    cursor = staff_client.get(f"/api/conversations/{conversation.pk}").json()[
        "next_messages_cursor"
    ]
    assert client.get("/api/recipient/conversation", {"before": cursor}).status_code == 400
    post(staff_client, f"/conversations/{conversation.pk}/revoke")
    assert client.get("/api/recipient/documents").status_code == 404


def test_outbox_wakes_only_after_commit_and_prioritizes_otp(
    org, settings, monkeypatch, django_capture_on_commit_callbacks
):
    settings.OUTBOX_IMMEDIATE_DISPATCH = True
    wake = Mock()
    monkeypatch.setattr("backend.apps.core.tasks.wake_delivery", wake)
    with django_capture_on_commit_callbacks(execute=True):
        job = queue_mail(org, {"challenge_id": "synthetic", "body": "fictional"})
        wake.assert_not_called()
    wake.assert_called_once_with(job.pk, urgent=True)
    wake.reset_mock()
    with django_capture_on_commit_callbacks(execute=True):
        with pytest.raises(RuntimeError):
            with transaction.atomic():
                queue_mail(org, {"body": "rollback"})
                raise RuntimeError("rollback")
    wake.assert_not_called()


def test_broker_failure_does_not_lose_committed_outbox(
    org, settings, monkeypatch, django_capture_on_commit_callbacks
):
    settings.OUTBOX_IMMEDIATE_DISPATCH = True
    monkeypatch.setattr(
        "backend.apps.core.tasks.deliver_job_task.apply_async", Mock(side_effect=OSError("offline"))
    )
    with django_capture_on_commit_callbacks(execute=True):
        job = queue_mail(org, {"body": "fictional"})
    assert DeliveryJob.objects.get(pk=job.pk).state == "queued"


def test_attachment_preparation_precedes_org_lock(staff_client, monkeypatch):
    upload = staff_client.post(
        "/api/attachments", {"file": SimpleUploadedFile("small.txt", b"fictional")}
    )
    assert upload.status_code == 201
    ident = upload.json()["id"]
    lock = conversations.lock_organization
    checked = []
    from backend.apps.core.models import Attachment

    def verify_lock(org):
        assert Attachment.objects.get(pk=ident).evidence_capture_id
        checked.append(True)
        return lock(org)

    monkeypatch.setattr(conversations, "lock_organization", verify_lock)
    assert compose(staff_client, attachments=[ident]).status_code == 201
    assert checked


def test_failed_broker_wakeup_is_bounded(monkeypatch):
    from backend.apps.core import tasks

    monkeypatch.setattr(tasks, "_wake_retry_at", 0)
    clock = Mock(return_value=100)
    monkeypatch.setattr(tasks.time, "monotonic", clock)
    publish = Mock(side_effect=OSError("offline"))
    monkeypatch.setattr(tasks.deliver_job_task, "apply_async", publish)
    for _ in range(100):
        tasks.wake_delivery("synthetic")
    assert publish.call_count == 1
    clock.return_value = 106
    tasks.wake_delivery("synthetic")
    assert publish.call_count == 2


def test_recipient_document_page_excludes_other_private_audiences(staff_client):
    from backend.tests.test_shared_mail import setup_group

    ident, first, second, blind = setup_group(staff_client)
    upload = first.post(
        "/api/recipient/attachments",
        {"file": SimpleUploadedFile("private.txt", b"fictional private")},
    )
    assert upload.status_code == 201
    file_id = upload.json()["id"]
    reply = post(
        first,
        "/recipient/conversation",
        {"body": "owner only", "attachments": [file_id], "reply_mode": "sender"},
    )
    assert reply.status_code == 201
    assert first.get("/api/recipient/documents").json()["count"] == 1
    for other in (second, blind):
        assert other.get("/api/recipient/documents").json()["count"] == 0
        assert other.get(f"/api/attachments/{file_id}").status_code == 404


def test_timing_logs_do_not_include_request_content(staff_client, settings, caplog):
    import logging

    settings.PERFORMANCE_TIMINGS = True
    settings.PERFORMANCE_LOG_THRESHOLD_MS = 0
    with caplog.at_level(logging.INFO, logger="securemail.performance"):
        response = staff_client.get("/api/conversations", {"q": "private-search-marker"})
    assert response.status_code == 200
    records = [r.getMessage() for r in caplog.records if r.name == "securemail.performance"]
    assert records
    assert all("private-search-marker" not in line and "@" not in line for line in records)
    assert '"database_calls"' in records[-1]
