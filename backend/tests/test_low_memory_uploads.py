"""Real encryption/upload roundtrip with the optional small-host limit."""

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from backend.tests.test_flows import post, recipient_access


@pytest.mark.django_db
def test_small_profile_recipient_upload_download_and_limit(staff_client, settings):
    settings.MAX_UPLOAD_BYTES = 5 * 1024 * 1024
    settings.DATA_UPLOAD_MAX_MEMORY_SIZE = 7 * 1024 * 1024
    recipient, _, _, _ = recipient_access(staff_client)
    for path in ("/api/document-service", "/recipient-api/document-service"):
        response = staff_client.get(path)
        assert response.status_code == 200
        assert response.json()["max_upload_bytes"] == settings.MAX_UPLOAD_BYTES
        assert response.json()["max_files"] == 10
    content = b"a" * settings.MAX_UPLOAD_BYTES
    uploaded = recipient.post(
        "/api/recipient/attachments",
        {"file": SimpleUploadedFile("demo.txt", content, content_type="text/plain")},
    )
    assert uploaded.status_code == 201, uploaded.content
    ident = uploaded.json()["id"]
    saved = post(recipient, "/recipient/conversation", {"attachments": [ident]})
    assert saved.status_code == 201, saved.content
    downloaded = staff_client.get(f"/api/attachments/{ident}")
    assert downloaded.status_code == 200
    assert downloaded.content == content
    for client, path in (
        (staff_client, "/api/attachments"),
        (recipient, "/api/recipient/attachments"),
    ):
        rejected = client.post(path, {"file": SimpleUploadedFile("large.txt", content + b"x")})
        assert rejected.status_code == 413
    # A lower future upload cap must not make existing documents unreadable.
    settings.MAX_UPLOAD_BYTES = 1024 * 1024
    assert staff_client.get(f"/api/attachments/{ident}").content == content
