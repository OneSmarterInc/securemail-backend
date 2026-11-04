"""Small mTLS client with bounded responses, no redirects or environment proxies."""

import http.client
import os
import socket
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path
from queue import Empty, LifoQueue
from urllib.parse import urlsplit

from backend.performance import timed
from backend.transport import tls

from .protocol import canonical, parse_object


class ServiceUnavailable(ValueError):
    pass


class LoopbackHTTPSConnection(http.client.HTTPSConnection):
    """Prefer the local service's IPv4 listener, retaining localhost TLS identity."""

    def connect(self):
        try:
            stream = socket.create_connection(
                ("127.0.0.1", self.port), self.timeout, self.source_address
            )
        except OSError:
            stream = socket.create_connection(("::1", self.port), self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(stream, server_hostname=self.host)
        except BaseException:
            stream.close()
            raise


class Client:
    def __init__(
        self,
        url: str,
        ca: str,
        cert: str,
        key: str,
        *,
        require_pq: bool = False,
        timeout: float = 10,
        _context=None,
    ):
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Use an HTTPS key-service origin.")
        self.host, self.port = parsed.hostname, parsed.port or 443
        self.require_pq = require_pq
        self.timeout = timeout
        self.tls = _context or tls.client_context(ca, cert, key, required=require_pq)
        self.lock = threading.Lock()
        self.connection = None
        self.last_used = 0.0
        self.connected_at = 0.0
        self.pid = os.getpid()

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def call(self, operation: str, **data) -> dict:
        # One leased connection per cached client; no socket is shared concurrently.
        with self.lock:
            return self._call(operation, **data)

    def _call(self, operation: str, **data) -> dict:
        if not operation.isascii() or not operation.replace("-", "").isalpha():
            raise ValueError("Invalid operation.")
        connection_class = (
            LoopbackHTTPSConnection if self.host == "localhost" else http.client.HTTPSConnection
        )
        if (
            self.pid != os.getpid()
            or time.monotonic() - self.last_used > 1
            or time.monotonic() - self.connected_at > 60
        ):
            self.close()
            self.pid = os.getpid()
        conn = self.connection
        if conn is None:
            conn = connection_class(self.host, self.port, context=self.tls, timeout=self.timeout)
        try:
            if conn.sock is None:
                conn.connect()
                tls.verify(conn.sock, required=self.require_pq)
                self.connected_at = time.monotonic()
            conn.request(
                "POST",
                "/v1/" + operation,
                body=canonical(data),
                headers={"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            body = response.read(1024 * 1024 + 1)
            if response.status != 200 or len(body) > 1024 * 1024:
                raise ServiceUnavailable("Key service refused the operation or is unavailable.")
            value = parse_object(body)
            if not isinstance(value, dict):
                raise ServiceUnavailable("Invalid key-service response.")
            if response.will_close:
                conn.close()
                self.connection = None
            else:
                self.connection = conn
                self.last_used = time.monotonic()
            return value
        except (OSError, http.client.HTTPException, ValueError) as exc:
            conn.close()
            self.connection = None
            raise ServiceUnavailable(
                "Key service operation failed; no fallback is permitted."
            ) from exc


class ClientPool:
    """Four bounded leases sharing one validated TLS context per identity."""

    def __init__(self, url, ca, cert, key, *, require_pq=False, timeout=10):
        self.timeout = timeout
        self.lock = threading.Lock()
        self.clients = LifoQueue(maxsize=4)
        context = None
        for _ in range(4):
            client = Client(
                url, ca, cert, key, require_pq=require_pq, timeout=timeout, _context=context
            )
            context = client.tls
            self.clients.put(client)
        self.closed = False
        self.admission = threading.Condition()
        self.waiters = deque()
        self.active = 0

    @timed("key_service")
    def call(self, operation, **data):
        ticket = object()
        with self.admission:
            if len(self.waiters) >= 64:
                raise ServiceUnavailable("Key service connection queue is full.")
            self.waiters.append(ticket)
            admitted = self.admission.wait_for(
                lambda: self.closed or (self.waiters[0] is ticket and self.active < 4),
                timeout=self.timeout,
            )
            self.waiters.remove(ticket)
            if not admitted or self.closed:
                self.admission.notify_all()
                raise ServiceUnavailable("Key service connection pool is busy or replaced.")
            self.active += 1
            client = self.clients.get_nowait()
            self.admission.notify_all()
        try:
            return client.call(operation, **data)
        finally:
            with self.admission:
                if self.closed:
                    client.close()
                self.clients.put(client)
                self.active -= 1
                self.admission.notify_all()

    def close(self):
        with self.admission:
            self.closed = True
            while True:
                try:
                    self.clients.get_nowait().close()
                except Empty:
                    break
            self.admission.notify_all()


_clients = OrderedDict()
_clients_lock = threading.Lock()


def pooled_client(url, ca, cert, key, *, require_pq=False, timeout=10):
    """Bounded per-process pool; certificate replacement invalidates the client.

    No retry is made after an ambiguous transport failure (including mutations).
    Connections and TLS contexts contain no unwrapped document keys.
    """
    files = tuple(
        (str(path), Path(path).stat().st_mtime_ns, Path(path).stat().st_size)
        for path in (ca, cert, key)
    )
    identity = (os.getpid(), url, files, require_pq, timeout)
    with _clients_lock:
        client = _clients.get(identity)
        if client is None or client.closed:
            client = ClientPool(url, ca, cert, key, require_pq=require_pq, timeout=timeout)
            _clients[identity] = client
            while len(_clients) > 8:
                _, old = _clients.popitem(last=False)
                with old.lock:
                    old.close()
        _clients.move_to_end(identity)
        return client
