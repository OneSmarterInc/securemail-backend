import hashlib
import io
import sqlite3
from datetime import timedelta

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from backend.apps.core import audit as audit_module
from backend.apps.core import crypto, storage
from backend.apps.core.archive_verify import rebuild_projection
from backend.apps.core.conversations import attachment_context
from backend.apps.core.models import Attachment, AuditArchive, Message
from backend.apps.core.operations import clean_staged, report
from backend.apps.core.services import audit
from backend.tests.test_flows import compose


class Archive:
    """Protocol fake: not proof of AWS IAM/Object Lock enforcement."""

    def __init__(self):
        self.objects = {}
        self.corrupt = False
        self.mode = "COMPLIANCE"

    def put_object(self, **kw):
        self.objects[kw["Key"]] = kw
        return {"VersionId": "version-1"}

    def get_object_retention(self, **kw):
        assert kw["VersionId"] == "version-1"
        return {
            "Retention": {
                "Mode": self.mode,
                "RetainUntilDate": self.objects[kw["Key"]]["ObjectLockRetainUntilDate"],
            }
        }

    def get_object(self, **kw):
        assert kw["VersionId"] == "version-1"
        return {"Body": io.BytesIO(b"corrupt" if self.corrupt else self.objects[kw["Key"]]["Body"])}


@pytest.mark.django_db
def test_archive_verification_projection_and_tampering(org, settings, monkeypatch, tmp_path):
    settings.AUDIT_BUCKET, settings.AUDIT_RETENTION_DAYS = "synthetic-archive", 30
    fake = Archive()
    monkeypatch.setattr(audit_module.boto3, "client", lambda *a, **k: fake)
    event = audit(org, None, "test.created", "test", "one")
    audit_module.archive_pending()
    archived = AuditArchive.objects.get(event=event)
    entry = {
        "event_id": str(event.pk),
        "organization": str(org.pk),
        "sequence": event.sequence,
        "object_key": archived.object_key,
        "version_id": archived.version_id,
        "digest": archived.digest,
        "retain_until": archived.retain_until.isoformat(),
    }
    destination = tmp_path / "projection.sqlite3"
    assert rebuild_projection(fake, settings.AUDIT_BUCKET, [entry], destination) == 1
    with sqlite3.connect(destination) as db:
        assert db.execute("SELECT action FROM events").fetchone()[0] == "test.created"
    # Rebuild never overwrites a previous recovery artifact.
    with pytest.raises(FileExistsError):
        rebuild_projection(fake, settings.AUDIT_BUCKET, [entry], destination)
    fake.corrupt = True
    with pytest.raises(ValueError):
        rebuild_projection(fake, settings.AUDIT_BUCKET, [entry], tmp_path / "bad.sqlite3")
    assert not (tmp_path / "bad.sqlite3").exists()
    new = audit(org, None, "test.pending", "test", "two")
    with pytest.raises(ValueError):
        audit_module.archive_pending()
    assert not AuditArchive.objects.filter(event=new).exists()
    fake.corrupt, fake.mode = False, "GOVERNANCE"
    with pytest.raises(ValueError):
        audit_module.archive_pending()
    assert not AuditArchive.objects.filter(event=new).exists()


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
    result = report(max_archive_age=0, min_free_bytes=10**30)
    assert "storage_free_space_low" in result["issues"]
    assert "archive_not_configured" in result["issues"]
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
