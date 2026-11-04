import hashlib
from datetime import timedelta

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from backend.apps.core import crypto, storage
from backend.apps.core.conversations import attachment_context
from backend.apps.core.models import Attachment, Message
from backend.apps.core.operations import clean_staged, report
from backend.apps.core.services import audit
from backend.tests.test_flows import compose


def test_failed_object_replacement_preserves_previous_bytes(settings, monkeypatch):
    storage.put("synthetic-object", b"previous ciphertext")

    def interrupted(*args):
        raise OSError("simulated failed replacement")

    monkeypatch.setattr(storage.os, "replace", interrupted)
    with pytest.raises(OSError):
        storage.put("synthetic-object", b"new ciphertext")
    assert storage.get("synthetic-object") == b"previous ciphertext"
    assert not list((settings.RUNTIME_DIR / "objects").glob(".upload-*"))


@pytest.mark.django_db
def test_cleanup_preserves_committed_and_recovers_failed_deletion(
    staff_client, settings, monkeypatch
):
    def upload():
        return staff_client.post(
            "/api/attachments", {"file": SimpleUploadedFile("sample.txt", b"sample")}
        ).json()["id"]

    kept, abandoned = upload(), upload()
    response = compose(staff_client, attachments=[kept])
    assert response.status_code == 201
    Attachment.objects.update(created_at=timezone.now() - timedelta(days=3))
    assert clean_staged(older_than_hours=24, limit=10, apply=False)["candidates"] == 1
    original_remove = storage.remove

    def fail(_):
        raise OSError("synthetic storage outage")

    monkeypatch.setattr(storage, "remove", fail)
    assert clean_staged(older_than_hours=24, limit=10, apply=True)["failed"] == 1
    assert Attachment.objects.get(pk=abandoned).state == "cleanup_pending"
    monkeypatch.setattr(storage, "remove", original_remove)
    assert clean_staged(older_than_hours=24, limit=10, apply=True)["deleted"] == 1
    assert Attachment.objects.get(pk=kept).message_id is not None
    row = Attachment.objects.select_related("message__conversation").get(pk=kept)
    assert (
        crypto.decrypt(storage.get(row.object_key).decode(), attachment_context(row)) == b"sample"
    )
    assert clean_staged(older_than_hours=24, limit=10, apply=True)["candidates"] == 0


@pytest.mark.django_db
def test_backlog_signals_and_object_restore(org, staff_client, settings):
    audit(org, None, "test.old", "test", "one")
    result = report(min_free_bytes=10**30)
    assert "storage_free_space_low" in result["issues"]
    assert "archive_not_configured" not in result["issues"]
    assert result["pending_archive"] == 0
    uploaded = staff_client.post(
        "/api/attachments", {"file": SimpleUploadedFile("restore.txt", b"restore me")}
    ).json()["id"]
    assert compose(staff_client, attachments=[uploaded]).status_code == 201
    row = Attachment.objects.select_related("message__conversation").get(pk=uploaded)
    saved_ciphertext = storage.get(row.object_key)
    saved_thread = row.message.conversation_id
    storage.remove(row.object_key)
    with pytest.raises(FileNotFoundError):
        storage.get(row.object_key)
    storage.put(row.object_key, saved_ciphertext)
    assert (
        hashlib.sha256(storage.get(row.object_key)).digest()
        == hashlib.sha256(saved_ciphertext).digest()
    )
    assert (
        crypto.decrypt(storage.get(row.object_key).decode(), attachment_context(row))
        == b"restore me"
    )
    assert Message.objects.get(pk=row.message_id).conversation_id == saved_thread
