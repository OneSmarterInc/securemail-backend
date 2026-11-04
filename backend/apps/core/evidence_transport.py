"""Bounded HTTPS retrieval pinned to validated public DNS addresses."""

import http.client
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

from .public_network import public_address


def checked_url(value: str) -> str:
    if len(value) > 4096 or any(ord(c) < 33 for c in value):
        raise ValueError("Enter an HTTPS source URL without spaces or control characters.")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.fragment
    ):
        raise ValueError("Use a public HTTPS URL on port 443 without credentials or a fragment.")
    return value


class PublicHTTPS(http.client.HTTPSConnection):
    def connect(self):
        addresses = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        if not addresses or any(not public_address(row[4][0]) for row in addresses):
            raise ValueError("Private or reserved network destinations are forbidden.")
        # One pinned address, no proxy environment variables and no second DNS lookup.
        family, kind, proto, _, address = addresses[0]
        stream = socket.socket(family, kind, proto)
        try:
            stream.settimeout(self.timeout)
            stream.connect(address)
            self.sock = self._context.wrap_socket(stream, server_hostname=self.host)
        except BaseException:
            stream.close()
            raise


def retrieve(url: str, *, limit: int, body: bytes | None = None) -> tuple[bytes, str, str]:
    deadline = time.monotonic() + 30
    for _ in range(4):
        checked_url(url)
        parsed = urlsplit(url)
        connection = PublicHTTPS(parsed.hostname, timeout=10, context=ssl.create_default_context())
        try:
            path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            headers = {"Accept-Encoding": "identity", "User-Agent": "OneSmarter-Evidence/1"}
            if body is not None:
                headers["Content-Type"] = "application/timestamp-query"
                headers["Accept"] = "application/timestamp-reply"
            connection.request("POST" if body is not None else "GET", path, body, headers)
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308} and body is None:
                location = response.getheader("Location")
                if not location:
                    raise ValueError("Source redirect has no destination.")
                url = urljoin(url, location)
                continue
            if (
                response.status != 200
                or response.getheader("Content-Encoding", "identity") != "identity"
            ):
                raise ValueError("Source did not return an uncompressed successful response.")
            chunks = []
            size = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Capture deadline exceeded.")
                if connection.sock:
                    connection.sock.settimeout(min(remaining, 10))
                chunk = response.read1(min(65536, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > limit:
                    raise ValueError("Capture exceeds the maximum response size.")
            return b"".join(chunks), url, response.getheader("Content-Type", "")
        finally:
            connection.close()
    raise ValueError("Too many source redirects.")
