"""A single trusted edge assertion, never a user-controlled forwarding chain."""

from ipaddress import ip_address

from django.conf import settings

from .http import Problem


def canonical_ip(value: str) -> str:
    if not value or "%" in value:
        raise ValueError("Missing IP or scoped address")
    address = ip_address(value)
    return str(getattr(address, "ipv4_mapped", None) or address)


def client_ip(request) -> str:
    peer = request.META.get("REMOTE_ADDR", "")
    unix_peer = not peer and settings.TRUSTED_PROXY_UNIX_SOCKET
    try:
        address = canonical_ip(peer) if peer else ""
        trusted = unix_peer or address in settings.TRUSTED_PROXY_IPS
        if trusted:
            return canonical_ip(request.META.get("HTTP_X_REAL_IP", ""))
        return canonical_ip(peer)
    except ValueError as exc:
        raise Problem("Invalid client address.", "invalid_client_address", 400) from exc
