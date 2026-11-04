"""Regression coverage for plaintext upload buffering."""

from pathlib import Path

import pytest
from django.core.exceptions import RequestDataTooBig
from django.core.files.uploadedfile import InMemoryUploadedFile, SimpleUploadedFile
from django.core.files.uploadhandler import StopFutureHandlers, TemporaryFileUploadHandler

from backend.apps.core import storage
from backend.apps.core.upload_handlers import BoundedMemoryUploadHandler
from backend.tests.test_flows import recipient_access


@pytest.mark.django_db
@pytest.mark.parametrize("recipient_mode", [False, True])
def test_large_upload_never_creates_plaintext_temp_file(
    staff_client, recipient_mode, settings, monkeypatch, tmp_path
):
    directory = tmp_path / "upload-temp"
    directory.mkdir()
    settings.FILE_UPLOAD_TEMP_DIR = str(directory)
    # Point the OS tempfile default here too, to detect fallback handlers.
    monkeypatch.setattr("tempfile.tempdir", str(directory))

    def no_disk_handler(*args, **kwargs):
        pytest.fail("Plaintext temporary upload handler was invoked")

    monkeypatch.setattr(TemporaryFileUploadHandler, "new_file", no_disk_handler)
    scanned = []
    original_scan = storage.validate_file

    def inspect_scan(name, data):
        assert list(directory.iterdir()) == []
        scanned.append(len(data))
        return original_scan(name, data)

    monkeypatch.setattr(storage, "validate_file", inspect_scan)
    client = recipient_access(staff_client)[0] if recipient_mode else staff_client
    path = "/api/recipient/attachments" if recipient_mode else "/api/attachments"
    content = b"PRIVATE-UPLOAD-MARKER\n" + b"a" * (2 * 1024 * 1024)
    response = client.post(
        path, {"file": SimpleUploadedFile("large.txt", content, content_type="text/plain")}
    )
    assert response.status_code == 201, response.content
    assert scanned == [len(content)]
    assert list(directory.iterdir()) == []


def start_file(handler):
    with pytest.raises(StopFutureHandlers):
        handler.new_file("file", "file.txt", "text/plain", None)


def test_memory_handler_bounds_actual_bytes_across_files(settings):
    settings.MAX_UPLOAD_BYTES = 8
    handler = BoundedMemoryUploadHandler()
    handler.handle_raw_input(None, {}, None, b"boundary")
    start_file(handler)
    handler.receive_data_chunk(b"12345", 0)
    first = handler.file_complete(5)
    assert isinstance(first, InMemoryUploadedFile)
    start_file(handler)
    handler.receive_data_chunk(b"678", 0)
    with pytest.raises(RequestDataTooBig):
        handler.receive_data_chunk(b"9", 3)
    assert handler.file.closed
    first.close()


def test_memory_handler_rejects_oversized_declared_request(settings):
    handler = BoundedMemoryUploadHandler()
    with pytest.raises(RequestDataTooBig):
        handler.handle_raw_input(None, {}, settings.DATA_UPLOAD_MAX_MEMORY_SIZE + 1, b"boundary")


def test_all_proxy_profiles_stream_without_disk_buffers():
    root = Path(__file__).resolve().parents[2]
    for name, locations in [("deploy/local-nginx.conf", 1), ("deploy/pq-nginx.conf", 2)]:
        config = (root / name).read_text()
        assert config.count("proxy_request_buffering off;") == locations
        assert config.count("proxy_buffering off;") == locations
        assert config.count("proxy_http_version 1.1;") == locations
        assert config.count("proxy_max_temp_file_size 0;") == locations


@pytest.mark.django_db
def test_oversize_upload_returns_explicit_error_without_temp_file(staff_client, settings, tmp_path):
    settings.MAX_UPLOAD_BYTES = 1024
    upload_dir = tmp_path / "only-uploads"
    upload_dir.mkdir()
    settings.FILE_UPLOAD_TEMP_DIR = str(upload_dir)
    response = staff_client.post(
        "/api/attachments",
        {"file": SimpleUploadedFile("large.txt", b"a" * 2048, content_type="text/plain")},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "upload_too_large"
    assert list(upload_dir.iterdir()) == []
