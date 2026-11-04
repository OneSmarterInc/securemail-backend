"""Shared destination policy before opening a socket; also enforce network egress ACLs."""

import ipaddress

NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address):
        if any(address in network for network in NAT64) or address.sixtofour or address.teredo:
            return False
        if address.ipv4_mapped:
            return address.ipv4_mapped.is_global
    return address.is_global
