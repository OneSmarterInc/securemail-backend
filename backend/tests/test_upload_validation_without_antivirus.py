import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from backend.apps.core import storage


@pytest.mark.django_db
def test_upload_has_no_malware_verdict_or_scanner_dependency(staff_client):
    assert not hasattr(storage, "scan")
    result = staff_client.post(
        "/api/attachments", {"file": SimpleUploadedFile("example.txt", b"Synthetic document")}
    )
    assert result.status_code == 201
    assert "scan_method" not in result.json()
    settings = staff_client.get("/api/settings").json()
    assert "scanner" not in settings and "antivirus_enabled" not in settings
    assert staff_client.post("/api/settings/checks").status_code == 404


@pytest.mark.django_db
def test_file_validation_and_size_limit_remain(staff_client, settings):
    settings.MAX_UPLOAD_BYTES = 8
    for name, value in [("bad.pdf", b"not-pdf"), ("large.txt", b"a" * 9), ("empty.txt", b"")]:
        response = staff_client.post("/api/attachments", {"file": SimpleUploadedFile(name, value)})
        assert response.status_code in {400, 413}
