"""Fail-closed policy regressions; actual handshakes live in check_pq_transport.py."""

import ssl
from unittest.mock import Mock

import pytest

from backend.transport import tls


@pytest.mark.parametrize(
    "group,version,reused",
    [
        ("X25519", "TLSv1.3", False),
        (None, "TLSv1.3", False),
        (tls.GROUP, "TLSv1.2", False),
        (tls.GROUP, "TLSv1.3", True),
    ],
)
def test_refuse_unverified_transport(group, version, reused):
    peer = Mock(session_reused=reused)
    peer.group.return_value = group
    peer.version.return_value = version
    with pytest.raises(ssl.SSLError):
        tls.verify(peer, required=True)


def test_unsupported_runtime_refuses_strict_mode():
    if hasattr(ssl.SSLContext, "set_groups"):
        return
    with pytest.raises(ValueError, match="Python 3.15"):
        tls.configure(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), required=True)
