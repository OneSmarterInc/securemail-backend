"""Bounded single-process HTTPS/mTLS service and independent custodian portal.

TLS negotiation and deployment review remain production gates. No HTTP mode.
Certificate allowlists are reread per request so revocation needs no restart.
"""

import hashlib
import ipaddress
import logging
import secrets
import select
import ssl
import threading
import time
import uuid
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag

from backend.transport import tls as transport_tls

from . import protocol as p
from .custodian_accounts import CustodianAccounts, directory_for
from .ownership import StoreOwnership
from .store import ConflictError, KeyStore, SealedError, require_synthetic_import

logger = logging.getLogger(__name__)

MAX_BODY = 131072
ROOT_OPERATIONS = {
    "unseal",
    "seal",
    "custody-status",
    "custody-audit",
    "rotate-root",
    "restore-candidate",
}
FIELDS = {
    "versions": {"organization"},
    "rotate": {"organization", "expected", "request_id"},
    "import": {"organization", "key_id", "private"},
    "wrap": {"organization", "context", "dek", "expected"},
    "unwrap": {"organization", "context", "wrapper"},
    "unwrap-batch": {"organization", "items"},
    "rewrap": {"organization", "context", "wrapper", "expected"},
    "unseal": {"secret"},
    "restore-candidate": {"secret", "destination_id"},
    "seal": set(),
    "custody-status": set(),
    "custody-audit": {"query", "actor", "operation", "sort", "direction", "page"},
    "rotate-root": {"secret", "expected"},
    "status": set(),
}


def strict_json(raw: bytes) -> dict:
    return p.parse_object(raw)


class Service:
    def __init__(self, store: KeyStore, policy: Path, origin: str, *, allow_http_loopback=False):
        parsed = urlsplit(origin)
        self.local_http = (
            allow_http_loopback
            and parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1"}
            and not parsed.username
            and not parsed.password
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
        )
        secure_origin = (
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
        )
        if not secure_origin and not self.local_http:
            raise ValueError("Configure the exact HTTPS portal origin without a trailing slash.")
        self.store, self.policy, self.origin = store, policy, origin
        self.accounts = CustodianAccounts(directory_for(policy))
        self.lock = threading.RLock()
        self.sessions: dict[str, dict] = {}
        self.rates: dict[str, tuple[float, int]] = {}
        self.denial_window = 0.0
        self.denial_count = 0
        self.denials: dict[tuple[str, str], int] = {}

    def flush_denials(self, *, force=False):
        with self.lock:
            now = time.monotonic()
            if not self.denials or (not force and now - self.denial_window < 60):
                return
            # Keep counters until their durable write succeeds.
            for (actor, event), count in list(self.denials.items()):
                try:
                    self.store.record_event(actor, f"denial_batch:{event}:count={count}")
                except Exception:
                    logger.error("key_service_denial_audit_unavailable")
                    return
                del self.denials[(actor, event)]
            self.denial_count = 0
            self.denial_window = now

    def identity(self, fingerprint: str) -> dict:
        policy = strict_json(self.policy.read_bytes())
        identity = policy.get("identities", {}).get(fingerprint)
        if not isinstance(identity, dict) or identity.get("expires_at", 0) <= time.time():
            raise PermissionError("Identity unavailable.")
        if not isinstance(identity.get("name"), str):
            raise PermissionError("Identity unavailable.")
        return identity

    def throttle(self, key: str, limit: int):
        with self.lock:
            now = time.monotonic()
            # Bound memory even with repeated attempts; peers require an accepted certificate.
            self.rates = {k: v for k, v in self.rates.items() if now - v[0] < 60}
            start, count = self.rates.get(key, (now, 0))
            if count >= limit:
                raise PermissionError("Rate limit exceeded.")
            self.rates[key] = (start, count + 1)

    def login(self, fp: str, identity: dict, body: dict) -> dict:
        self.throttle("login:" + fp, 60)
        if (
            not {"username", "password", "code"} <= set(body)
            or set(body) - {"username", "password", "code", "new_password", "confirmation"}
            or identity.get("role") != "custodian"
        ):
            raise PermissionError("Login failed.")
        if isinstance(body["username"], str):
            self.throttle(
                "login-account:"
                + hashlib.sha256(body["username"].strip().lower().encode()).hexdigest(),
                5,
            )
        account = self.accounts.login(
            body["username"],
            body["password"],
            body["code"],
            new_password=body.get("new_password", ""),
            confirmation=body.get("confirmation", ""),
        )
        if account.get("enrollment_required"):
            return account
        with self.lock:
            self.sessions = {
                k: v
                for k, v in self.sessions.items()
                if v["expires"] > time.time() and v["account"]["id"] != account["id"]
            }
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.sessions[token] = {
                "fp": fp,
                "csrf": csrf,
                "expires": time.time() + 300,
                "policy_digest": hashlib.sha256(p.canonical(identity)).hexdigest(),
                "account": account,
            }
        return {"token": token, "csrf": csrf, "account": account}

    def authenticate_session(self, fp: str, identity: dict, cookie: str, csrf: str):
        cookies = SimpleCookie()
        cookies.load(cookie)
        token = cookies.get("osm_custodian")
        with self.lock:
            session = self.sessions.get(token.value if token else "")
            if (
                identity.get("role") != "custodian"
                or not session
                or session["fp"] != fp
                or session["expires"] <= time.time()
                or session["policy_digest"] != hashlib.sha256(p.canonical(identity)).hexdigest()
                or not secrets.compare_digest(session["csrf"], csrf)
            ):
                raise PermissionError("Sign in again.")
            return self.accounts.current(session["account"]["id"], session["account"]["revision"])

    def dispatch(self, op: str, data: dict, identity: dict) -> dict:
        optional = {"active", "after"} if op == "versions" else set()
        if op in {"unseal", "restore-candidate"}:
            optional = {"integrity_override_reason"}
        if op == "custody-audit":
            optional = {"from", "to"}
        if op not in FIELDS or not FIELDS[op] <= set(data) or set(data) - FIELDS[op] - optional:
            raise ValueError("Unsupported operation or fields.")
        permission = (
            "unwrap" if op == "unwrap-batch" else "custody-status" if op == "custody-audit" else op
        )
        if permission not in identity.get("operations", []):
            raise PermissionError("Operation denied.")
        if op in ROOT_OPERATIONS and identity.get("role") != "custodian":
            raise PermissionError("Custodian required.")
        if op in {"rotate", "import"} and identity.get("role") != "maintenance":
            raise PermissionError("Maintenance identity required.")
        org = data.get("organization")
        if org is not None:
            if not isinstance(org, str) or str(uuid.UUID(org)) != org:
                raise ValueError("Invalid organization.")
            if org not in identity.get("organizations", []):
                raise PermissionError("Organization denied.")
        actor = identity["name"]
        if op == "status":
            return self.store.status()
        if op == "custody-status":
            return {**self.store.custody_status(), "custodian": identity.get("display_name", actor)}
        if op == "custody-audit":
            return self.accounts.audit(self.store.path, data)
        if op == "unseal":
            options = {}
            if "integrity_override_reason" in data:
                if not hasattr(self.store, "restore_for_custodian"):
                    raise PermissionError("Integrity override requires the audit candidate")
                options["override_reason"] = data["integrity_override_reason"]
            self.store.unseal(p.decode(data["secret"], 32), actor, **options)
            return self.store.status()
        if op == "restore-candidate":
            if not hasattr(self.store, "restore_for_custodian"):
                raise PermissionError("Candidate recovery only")
            return self.store.restore_for_custodian(
                p.decode(data["secret"], 32),
                data["destination_id"],
                actor,
                override_reason=data.get("integrity_override_reason"),
            )
        if op == "seal":
            self.store.seal(actor)
            return self.store.status()
        if op == "rotate-root":
            return self.store.rotate_root(p.decode(data["secret"], 32), data["expected"], actor)
        if op == "versions":
            versions = self.store.list_versions(
                org, active=data.get("active", False), after=data.get("after", "")
            )
            return {
                "versions": versions,
                "next_cursor": versions[-1]["id"] if len(versions) == 100 else None,
            }
        if op == "rotate":
            return self.store.rotate(org, data["expected"], data["request_id"], actor)
        if op == "import":
            require_synthetic_import()
            return self.store.import_version(
                org, data["key_id"], p.decode(data["private"], 96), actor
            )
        if op == "wrap":
            return self.store.wrap(
                org, data["context"], p.decode(data["dek"], 32), data["expected"], actor
            )
        if op == "unwrap-batch":
            return {
                "deks": [
                    p.encode(value) for value in self.store.unwrap_batch(org, data["items"], actor)
                ]
            }
        if op == "unwrap":
            return {
                "dek": p.encode(self.store.unwrap(org, data["context"], data["wrapper"], actor))
            }
        return self.store.rewrap(org, data["context"], data["wrapper"], data["expected"], actor)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OneSmarterKeyService"
    sys_version = ""

    def log_message(self, *args):
        # No access log containing URLs, cookies, request bodies, or secrets.
        pass

    def response(self, status: int, value, *, content_type="application/json", cookie=None):
        payload = p.canonical(value) if content_type == "application/json" else value
        # Rejected requests may have an unread body: never parse it as a next request.
        if status != 200:
            self.close_connection = True
        self.send_response(status)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(payload)

    def peer(self):
        cert = self.connection.getpeercert(binary_form=True)
        if not cert:
            raise PermissionError("Client certificate required.")
        fp = hashlib.sha256(cert).hexdigest()
        self.peer_fingerprint = fp
        service = self.server.service
        # Revoked/unlisted identities must never consume authorized workloads' budget.
        identity = service.identity(fp)
        # Separate custody capacity from workload traffic. Policy limits are
        # operator-controlled, never supplied by an API caller.
        custody = identity.get("role") == "custodian"
        bulk = self.path == "/v1/unwrap-batch"
        category = "custody" if custody else "bulk" if bulk else "workload"
        default_limit = 600 if custody else 3000 if bulk else 6000
        limit = identity.get("rate_limits", {}).get(category, default_limit)
        if type(limit) is not int or not 1 <= limit <= default_limit:
            raise PermissionError("Invalid identity rate policy.")
        with service.lock:
            # Preflight both limits before charging either bucket.
            now = time.monotonic()
            keys = (
                ("traffic:" + category + ":" + fp, limit),
                ("global:" + category, default_limit),
            )
            for key, cap in keys:
                start, count = service.rates.get(key, (now, 0))
                if now - start < 60 and count >= cap:
                    raise PermissionError("Rate limit exceeded.")
            for key, cap in keys:
                service.throttle(key, cap)
        return fp, identity

    def do_GET(self):
        try:
            _, identity = self.peer()
            if identity.get("role") != "custodian":
                raise PermissionError("Custodian access required.")
            files = {
                "/": ("portal.html", "text/html; charset=utf-8"),
                "/portal.js": ("portal.js", "text/javascript; charset=utf-8"),
                "/custodian-qr.js": ("static/custodian-qr.js", "text/javascript; charset=utf-8"),
                "/portal.css": ("portal.css", "text/css; charset=utf-8"),
            }
            if self.path not in files:
                self.response(404, {"error": "not_found"})
                return
            name, mime = files[self.path]
            self.response(200, (Path(__file__).parent / name).read_bytes(), content_type=mime)
        except (PermissionError, ValueError, OSError):
            self.response(403, {"error": "access_denied"})

    def do_POST(self):
        service = self.server.service
        op, identity = "invalid", None
        try:
            fp, identity = self.peer()
            if (
                self.headers.get("Transfer-Encoding")
                or len(self.headers.get_all("Content-Length", [])) != 1
            ):
                raise ValueError("Invalid framing.")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY or self.headers.get("Content-Type") != "application/json":
                raise ValueError("Invalid request.")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete request.")
            data = strict_json(raw)
            if self.path == "/login":
                op = "login"
                if self.headers.get("Origin") != service.origin:
                    raise PermissionError("Origin denied.")
                login = service.login(fp, identity, data)
                if login.get("enrollment_required"):
                    self.response(200, login)
                    return
                account = login["account"]
                service.store.record_event(
                    "custodian:" + account["id"] + ":" + account["username"], "login_success"
                )
                self.response(
                    200,
                    {"csrf": login["csrf"]},
                    cookie=f"osm_custodian={login['token']}; Path=/; {'Secure; ' if not service.local_http else ''}HttpOnly; SameSite=Strict; Max-Age=300",
                )
                return
            if not self.path.startswith("/v1/"):
                raise ValueError("Unknown route.")
            op = self.path[4:]
            if op in ROOT_OPERATIONS or op == "logout":
                if self.headers.get("Origin") != service.origin:
                    raise PermissionError("Origin denied.")
                account = service.authenticate_session(
                    fp,
                    identity,
                    self.headers.get("Cookie", ""),
                    self.headers.get("X-CSRFToken", ""),
                )
                identity = {
                    **identity,
                    "name": "custodian:" + account["id"] + ":" + account["username"],
                    "display_name": account["display_name"],
                }
            if op == "logout":
                if data:
                    raise ValueError("Unexpected fields.")
                with service.lock:
                    service.sessions = {
                        k: v
                        for k, v in service.sessions.items()
                        if v["account"]["id"] != account["id"]
                    }
                service.accounts.event(account["username"], "logout")
                self.response(
                    200,
                    {"logged_out": True},
                    cookie=f"osm_custodian=; Path=/; {'Secure; ' if not service.local_http else ''}HttpOnly; SameSite=Strict; Max-Age=0",
                )
                return
            if op in {"unseal", "rotate-root", "restore-candidate"}:
                service.throttle("custody:" + fp, 5)
            result = service.dispatch(op, data, identity)
            self.response(200, result)
        except SealedError:
            self.response(503, {"error": "sealed"})
        except ConflictError:
            self.response(409, {"error": "conflict"})
        except PermissionError:
            self.audit_failure(identity, "access_denied")
            self.response(403, {"error": "access_denied"})
        except (ValueError, TypeError, KeyError, InvalidTag):
            self.audit_failure(identity, "invalid_request_or_material")
            self.response(400, {"error": "invalid_request_or_material"})
        except Exception as exc:
            # No exception text/traceback, request body, certificate or key material.
            incident = str(uuid.uuid4())
            logger.error(
                "key_service_unexpected incident=%s exception_type=%s", incident, type(exc).__name__
            )
            self.response(503, {"error": "service_unavailable", "incident_id": incident})

    def audit_failure(self, identity, event):
        service = self.server.service
        actor = (
            identity["name"]
            if identity
            else "certificate:" + getattr(self, "peer_fingerprint", "unknown")
        )
        with service.lock:
            key = (actor, event)
            if key not in service.denials and len(service.denials) >= 128:
                key = ("overflow-unlisted-identities", "access_denied")
            service.denials[key] = service.denials.get(key, 0) + 1
            service.denial_count += 1
        service.flush_denials()


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = False
    request_queue_size = 32

    def __init__(self, address, service: Service, tls: ssl.SSLContext, *, require_pq=False):
        self.service, self.tls = service, tls
        self.require_pq = require_pq
        transport_tls.configure(tls, required=require_pq)
        self.slots = threading.BoundedSemaphore(16)
        self.authenticated_slots = threading.BoundedSemaphore(64)
        self.custodian_slots = threading.BoundedSemaphore(8)
        self.denied_slots = threading.BoundedSemaphore(4)
        self.connection_lock = threading.Lock()
        self.connections_by_ip: dict[str, int] = {}
        self.handshake_deadline_seconds = 2.0
        self.connections_per_ip = 4
        self.ownership = StoreOwnership(service.store.path)
        try:
            super().__init__(address, Handler)
        except BaseException:
            self.ownership.close()
            raise

    def service_actions(self):
        self.service.flush_denials()
        tick = getattr(self.service.store, "tick", None)
        if tick is not None:
            try:
                tick()
            except Exception:
                logger.error("candidate_checkpoint_timer_failed_service_sealed")

    def server_close(self):
        try:
            # Wait for request threads before allowing another service owner.
            super().server_close()
            self.service.flush_denials(force=True)
        finally:
            self.ownership.close()

    def process_request(self, request, client_address):
        address = ipaddress.ip_address(client_address[0])
        peer = str(address.ipv4_mapped or address) if address.version == 6 else str(address)
        deadline = time.monotonic() + self.handshake_deadline_seconds
        with self.connection_lock:
            admitted = self.connections_by_ip.get(
                peer, 0
            ) < self.connections_per_ip and self.slots.acquire(blocking=False)
            if admitted:
                self.connections_by_ip[peer] = self.connections_by_ip.get(peer, 0) + 1
        if not admitted:
            request.close()
            return
        try:
            # Carry admission metadata into the worker, including scheduling time.
            super().process_request(request, (client_address, peer, deadline))
        except BaseException:
            request.close()
            self.release_connection(peer)
            raise

    def release_connection(self, peer):
        with self.connection_lock:
            remaining = self.connections_by_ip[peer] - 1
            if remaining:
                self.connections_by_ip[peer] = remaining
            else:
                del self.connections_by_ip[peer]
            self.slots.release()

    def handshake(self, request, deadline):
        request.setblocking(False)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("TLS handshake deadline exceeded")
            try:
                request.do_handshake()
                if time.monotonic() >= deadline:
                    raise TimeoutError("TLS handshake deadline exceeded")
                return
            except ssl.SSLWantReadError:
                readable, writable = [request], []
            except ssl.SSLWantWriteError:
                readable, writable = [], [request]
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not any(select.select(readable, writable, [], remaining)[:2]):
                raise TimeoutError("TLS handshake deadline exceeded")

    def process_request_thread(self, request, client_address):
        original_address, peer, deadline = client_address
        handshake_admitted = True
        authenticated = False
        try:
            request = self.tls.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
            self.handshake(request, deadline)
            transport_tls.verify(request, required=self.require_pq)
            # Idle authenticated connections must not hold pre-TLS admission slots.
            cert = request.getpeercert(binary_form=True)
            try:
                identity = self.service.identity(hashlib.sha256(cert).hexdigest())
            except PermissionError:
                identity = None
            slots = (
                self.denied_slots
                if identity is None
                else self.custodian_slots
                if identity.get("role") == "custodian"
                else self.authenticated_slots
            )
            self.release_connection(peer)
            handshake_admitted = False
            authenticated = slots.acquire(blocking=False)
            if not authenticated:
                return
            request.settimeout(2)
            super().process_request_thread(request, original_address)
        except (OSError, ssl.SSLError, PermissionError, ValueError):
            request.close()
        finally:
            request.close()
            if handshake_admitted:
                self.release_connection(peer)
            if authenticated:
                slots.release()


def tls_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    context.load_verify_locations(ca)
    context.verify_mode = ssl.CERT_REQUIRED
    return context
