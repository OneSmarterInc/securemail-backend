from unittest.mock import Mock

import pytest

from backend.keyservice.server import Service


@pytest.mark.parametrize(
    "origin,allow",
    [
        ("http://localhost:5173", False),
        ("http://example.com:5173", True),
        ("http://localhost:5173/path", True),
        ("http://user@localhost:5173", True),
        ("https://example.com/path", False),
    ],
)
def test_reject_unapproved_maintenance_origin(tmp_path, origin, allow):
    with pytest.raises(ValueError):
        Service(Mock(), tmp_path / "policy.json", origin, allow_http_loopback=allow)


def test_http_origin_is_explicit_local_preview_only(tmp_path):
    service = Service(
        Mock(), tmp_path / "policy.json", "http://localhost:5173", allow_http_loopback=True
    )
    assert service.local_http
    secure = Service(Mock(), tmp_path / "policy.json", "https://portal.example.com")
    assert not secure.local_http
