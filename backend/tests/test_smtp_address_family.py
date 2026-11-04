import socket
from unittest.mock import Mock

import pytest

from backend.apps.core.smtp_settings import public_socket


def test_ipv4_only_still_validates_and_pins_destination(settings, monkeypatch):
    settings.SMTP_IPV4_ONLY = True
    resolve = Mock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 587))])
    stream = Mock()
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", Mock(return_value=stream))
    assert public_socket("smtp.example.test", 587, 10) is stream
    assert resolve.call_args.kwargs["family"] == socket.AF_INET
    stream.connect.assert_called_once_with(("8.8.8.8", 587))


def test_ipv4_only_rejects_private_address(settings, monkeypatch):
    settings.SMTP_IPV4_ONLY = True
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 587))]),
    )
    with pytest.raises(OSError, match="public addresses"):
        public_socket("smtp.example.test", 587, 10)


def test_default_retains_dual_stack_validation(settings, monkeypatch):
    settings.SMTP_IPV4_ONLY = False
    resolve = Mock(
        return_value=[(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("64:ff9b::808:808", 587))]
    )
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    with pytest.raises(OSError, match="public addresses"):
        public_socket("smtp.example.test", 587, 10)
    assert resolve.call_args.kwargs["family"] == socket.AF_UNSPEC
