import io
import json
import socket
import zipfile

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command

from backend.apps.core import crypto, evidence, evidence_transport
from backend.apps.core.models import Attachment, EvidenceCapture
from backend.tests.test_flows import compose, post

pytestmark = pytest.mark.django_db


def submitted(client, **metadata):
    metadata = {
        "source_url": "https://example.com/original.txt",
        "downloaded_at": "2026-01-01T12:00:00Z",
        **metadata,
    }
    response = client.post(
        "/api/attachments",
        {
            "file": SimpleUploadedFile(
                "original.txt", b"original bytes", content_type="text/plain"
            ),
            **metadata,
        },
    )
    assert response.status_code == 201, response.content
    attachment = Attachment.objects.get(pk=response.json()["id"])
    result = compose(client, attachments=[str(attachment.pk)])
    assert result.status_code == 201, result.content
    attachment.refresh_from_db()
    return attachment


def test_original_hash_catalog_private_encrypted_bundle_and_export(staff_client, admin_client):
    row = submitted(
        staff_client,
        source_url="https://example.com/original.txt",
        downloaded_at="2026-01-01T12:00:00Z",
    )
    capture = row.evidence_capture
    from backend.apps.core.integrity import tag

    assert row.sha256 == tag(row.organization_id, b"original bytes")
    assert row.sha256 != evidence.digest(b"original bytes")
    raw = evidence.path_for(capture).read_bytes()
    assert b"original bytes" not in raw and b"example.com" not in raw
    catalog = staff_client.get("/api/evidence").json()
    assert catalog["results"][0]["provenance"] == "uploader_declared"
    assert catalog["results"][0]["timestamp_state"] == "pending"
    assert admin_client.get("/api/evidence").json()["count"] == 0
    assert admin_client.get(f"/api/evidence/{capture.pk}/export").status_code == 404
    export = staff_client.get(f"/api/evidence/{capture.pk}/export")
    assert export.status_code == 200
    with zipfile.ZipFile(io.BytesIO(export.content)) as bundle:
        assert bundle.read("original/original.txt") == b"original bytes"
        assert json.loads(bundle.read("manifest.json"))["sha256"] == evidence.digest(
            b"original bytes"
        )
        assert b"PENDING" in bundle.read("README.txt")


def test_no_overwrite_and_corruption_refuses_export(staff_client):
    row = submitted(staff_client)
    target = evidence.path_for(row.evidence_capture)
    with pytest.raises(FileExistsError):
        evidence.preserve(target, b"replacement")
    target.write_bytes(b"host-admin tampering")
    assert staff_client.get(f"/api/evidence/{row.evidence_capture_id}/export").status_code == 503


def test_bcc_copies_share_one_original_capture(staff_client):
    upload = staff_client.post(
        "/api/attachments",
        {
            "file": SimpleUploadedFile("a.txt", b"data"),
            "source_url": "https://example.com/a.txt",
            "downloaded_at": "2026-01-01T12:00:00Z",
        },
    )
    response = compose(
        staff_client,
        to=["a@example.com", "b@example.com"],
        bcc=["blind@example.com"],
        attachments=[upload.json()["id"]],
    )
    assert response.status_code == 201, response.content
    assert EvidenceCapture.objects.count() == 1
    assert Attachment.objects.filter(evidence_capture__isnull=False).count() == 2


def test_sealed_archive_read_fails_closed(staff_client, monkeypatch):
    row = submitted(staff_client)

    def sealed(*args, **kwargs):
        raise crypto.CryptoUnavailable()

    monkeypatch.setattr(crypto, "decrypt", sealed)
    assert staff_client.get("/api/evidence").status_code == 503
    assert staff_client.get(f"/api/evidence/{row.evidence_capture_id}/export").status_code == 503


def test_server_capture_records_actual_download(staff_client, monkeypatch):
    monkeypatch.setattr(
        evidence,
        "retrieve",
        lambda *a, **k: (b"captured file", "https://example.com/final.txt", "text/plain"),
    )
    result = post(
        staff_client, "/evidence/capture", {"source_url": "https://example.com/source.txt"}
    )
    assert result.status_code == 201, result.content
    response = compose(staff_client, attachments=[result.json()["id"]])
    assert response.status_code == 201
    entry = staff_client.get("/api/evidence").json()["results"][0]
    assert entry["provenance"] == "server_download"
    assert entry["final_url"] == "https://example.com/final.txt"
    assert entry["downloaded_at"]


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/a",
        "https://u:p@example.com/a",
        "https://example.com:444/a",
        "file:///etc/passwd",
    ],
)
def test_invalid_source_urls(url):
    with pytest.raises(ValueError):
        evidence_transport.checked_url(url)


def test_ssrf_private_resolution_is_rejected(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError):
        evidence_transport.retrieve("https://example.com/file", limit=1024)


def test_unconfigured_tsa_never_claims_verified(staff_client):
    row = submitted(staff_client)
    with pytest.raises(ValueError, match="not configured"):
        evidence.timestamp_capture(row.evidence_capture_id)
    row.evidence_capture.refresh_from_db()
    assert row.evidence_capture.timestamp_state == "pending"


def test_backfill_does_not_invent_source_or_change_file(staff_client, monkeypatch):
    original = evidence.capture_attachment
    monkeypatch.setattr(evidence, "capture_attachment", lambda *a, **k: None)
    row = submitted(staff_client)
    Attachment.objects.filter(pk=row.pk).update(sha256="", source_metadata_ciphertext="")
    monkeypatch.setattr(evidence, "capture_attachment", original)
    call_command("evidence_preserve", apply=True, stdout=io.StringIO())
    row.refresh_from_db()
    manifest, content = evidence.read_bundle(row.evidence_capture)
    assert content == b"original bytes"
    assert manifest["source_url"] is None and manifest["downloaded_at"] is None
    assert manifest["provenance"] == "legacy_unknown"
    call_command("evidence_preserve", apply=True, stdout=io.StringIO())
    assert EvidenceCapture.objects.count() == 1


def test_catalog_csv_is_scoped_and_has_capture_fields(staff_client, admin_client):
    submitted(staff_client, source_url="https://example.com/file")
    response = staff_client.get("/api/evidence?export=csv")
    assert response.status_code == 200
    assert b"sha256" in response.content and b"https://example.com/file" in response.content
    assert b"https://example.com/file" not in admin_client.get("/api/evidence?export=csv").content


@pytest.mark.parametrize(
    "metadata",
    [
        {"source_url": "https://example.com/file"},
        {"downloaded_at": "2026-01-01T12:00:00Z"},
        {"source_url": "https://example.com/file", "downloaded_at": "2026-01-01T12:00:00"},
        {"source_url": "https://example.com/file", "downloaded_at": "2999-01-01T12:00:00Z"},
    ],
)
def test_upload_requires_source_and_valid_download_time(staff_client, metadata):
    before = Attachment.objects.count()
    response = staff_client.post(
        "/api/attachments",
        {
            "file": SimpleUploadedFile("source.txt", b"source bytes", content_type="text/plain"),
            **metadata,
        },
    )
    assert response.status_code == 400
    assert Attachment.objects.count() == before


def test_staged_file_without_provenance_cannot_be_finalized(staff_client):
    response = staff_client.post(
        "/api/attachments",
        {
            "file": SimpleUploadedFile("source.txt", b"source bytes", content_type="text/plain"),
            "source_url": "https://example.com/file",
            "downloaded_at": "2026-01-01T12:00:00Z",
        },
    )
    assert response.status_code == 201
    row = Attachment.objects.get(pk=response.json()["id"])
    Attachment.objects.filter(pk=row.pk).update(source_metadata_ciphertext="")
    result = compose(staff_client, attachments=[str(row.pk)])
    assert result.status_code == 400
    assert EvidenceCapture.objects.count() == 0


def test_message_attachment_without_source_is_recorded_as_upload_only(staff_client):
    response = staff_client.post(
        "/api/attachments",
        {
            "file": SimpleUploadedFile(
                "message.txt", b"message attachment", content_type="text/plain"
            ),
        },
    )
    assert response.status_code == 201
    row = Attachment.objects.get(pk=response.json()["id"])
    result = compose(staff_client, attachments=[str(row.pk)])
    assert result.status_code == 201
    row.refresh_from_db()
    manifest, content = evidence.read_bundle(row.evidence_capture)
    assert content == b"message attachment"
    assert manifest["provenance"] == "upload_only"
    assert manifest["source_url"] is None
    assert manifest["downloaded_at"] is None
    assert manifest["sha256"] == evidence.digest(content)


def test_document_table_scoped_sort_and_original_download(staff_client, admin_client):
    row = submitted(staff_client)
    response = staff_client.get("/api/evidence?view=documents&sort=uploaded_at")
    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["id"] == str(row.pk)
    assert result["filename"] == "original.txt"
    assert result["conversation_id"] == str(row.message.conversation_id)
    assert result["sender_email"]
    assert result["uploaded_at"]
    assert admin_client.get("/api/evidence?view=documents").json()["count"] == 0
    assert staff_client.get("/api/evidence?view=documents&sort=invalid").status_code == 400
    download = staff_client.get(f"/api/attachments/{row.pk}")
    assert download.status_code == 200
    assert download.content == b"original bytes"


def test_document_search_matches_metadata_before_pagination(staff_client):
    row = submitted(staff_client)
    data = staff_client.get("/api/evidence?view=documents").json()["results"][0]
    for query in (
        "original.txt",
        data["sender_email"],
        data["conversation"],
        row.created_at.date().isoformat(),
    ):
        assert (
            staff_client.get("/api/evidence", {"view": "documents", "q": query}).json()["count"]
            == 1
        )
    assert staff_client.get("/api/evidence?view=documents&q=unmatched-string").json()["count"] == 0
