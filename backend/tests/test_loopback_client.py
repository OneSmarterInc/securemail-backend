import ssl
from unittest.mock import Mock

import pytest

from backend.keyservice.client import LoopbackHTTPSConnection


def test_ipv4_preference_preserves_localhost_certificate_identity(monkeypatch):
    stream = Mock()
    connect = Mock(return_value=stream)
    monkeypatch.setattr("backend.keyservice.client.socket.create_connection", connect)
    connection = LoopbackHTTPSConnection("localhost", 8443, timeout=3)
    assert connection._context.check_hostname
    assert connection._context.verify_mode == ssl.CERT_REQUIRED
    connection._context = Mock()
    connection.connect()
    assert connect.call_args.args[0] == ("127.0.0.1", 8443)
    connection._context.wrap_socket.assert_called_once_with(stream, server_hostname="localhost")


def test_certificate_failure_closes_socket_without_fallback(monkeypatch):
    stream = Mock()
    connect = Mock(return_value=stream)
    monkeypatch.setattr("backend.keyservice.client.socket.create_connection", connect)
    connection = LoopbackHTTPSConnection("localhost", 8443, timeout=3)
    connection._context = Mock()
    connection._context.wrap_socket.side_effect = ssl.SSLCertVerificationError()
    with pytest.raises(ssl.SSLCertVerificationError):
        connection.connect()
    stream.close.assert_called_once()
    assert connect.call_count == 1
