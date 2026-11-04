import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from backend.keyservice import protocol as p
from backend.keyservice.client import Client, ServiceUnavailable
from backend.keyservice.server import Server, Service, strict_json, tls_context
from backend.keyservice.store import ConflictError, KeyStore, SealedError


@pytest.mark.skipif(
    os.environ.get("RUN_KEY_PORTAL_BROWSER") != "1", reason="Opt-in local Edge browser check"
)
def test_custodian_browser(live_service):
    live = live_service
    import sqlite3
    from contextlib import closing

    with closing(sqlite3.connect(live["service"].accounts.path)) as db, db:
        db.execute("UPDATE accounts SET password_setup=1")
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        ["node", str(root / "scripts/check_key_portal.mjs")],
        input=json.dumps(
            {
                "origin": live["origin"],
                "cert": str(live["certs"]["custodian"][0]),
                "key": str(live["certs"]["custodian"][1]),
                "password": live["password"],
                "totp_seed": live["totp_seed"].hex(),
                "new_password": secrets.token_urlsafe(24),
                "secret": p.encode(live["secret"]),
                "screenshot": str(root / ".runtime/key-custody.png"),
            }
        ),
        text=True,
        capture_output=True,
        timeout=90,
        cwd=root,
    )
    assert result.returncode == 0, result.stderr
    assert live["store"].status()["sealed"] is True


@pytest.fixture
def vault(tmp_path):
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "vault.sqlite3", secret, backup_directory=tmp_path / "backups"
    )
    return store, secret


def provision(store):
    org = str(uuid.uuid4())
    key = store.rotate(org, None, str(uuid.uuid4()), "test-custodian")
    context = f"secure-mail:v1:organization={org}:document=sara"
    return org, key, context


def test_sealed_start_wrong_secret_recovery_and_no_disk_plaintext(vault):
    store, secret = vault
    assert store.status()["sealed"]
    with pytest.raises(InvalidTag):
        store.unseal(secrets.token_bytes(32), "custodian")
    with pytest.raises(SealedError):
        store.list_versions(str(uuid.uuid4()))
    store.unseal(secret, "custodian")
    org, key, context = provision(store)
    dek = secrets.token_bytes(32)
    envelope = store.wrap(org, context, dek, key["id"], "workload")
    assert store.unwrap(org, context, envelope, "workload") == dek
    root = store.root
    for path in store.path.parent.glob("vault.sqlite3*"):
        content = path.read_bytes()
        assert root not in content and secret not in content and dek not in content
    restarted = KeyStore(store.path)
    assert restarted.status()["sealed"]
    restarted.unseal(secret, "custodian")
    assert restarted.unwrap(org, context, envelope, "workload") == dek
    restarted.seal("custodian")
    with pytest.raises(SealedError):
        restarted.unwrap(org, context, envelope, "workload")


def test_rotation_idempotency_conflicts_and_concurrent_reads(vault):
    store, secret = vault
    store.unseal(secret, "custodian")
    org, old, context = provision(store)
    dek = secrets.token_bytes(32)
    envelope = store.wrap(org, context, dek, old["id"], "worker")
    request_id = str(uuid.uuid4())

    def rotate():
        return store.rotate(org, old["id"], request_id, "maintenance")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: rotate(), range(8)))
        assert len({result["id"] for result in results}) == 1
        assert all(
            item == dek
            for item in pool.map(
                lambda _: store.unwrap(org, context, envelope, "worker"), range(20)
            )
        )
    new = results[0]
    with pytest.raises(ConflictError):
        store.rotate(org, old["id"], str(uuid.uuid4()), "maintenance")
    with pytest.raises(ConflictError):
        store.rotate(str(uuid.uuid4()), None, request_id, "maintenance")
    replacement = store.rewrap(org, context, envelope, new["id"], "maintenance")
    assert store.unwrap(org, context, replacement, "worker") == dek
    assert replacement["key_id"] == new["id"]
    with pytest.raises(ConflictError):
        store.wrap(org, context, dek, old["id"], "worker")


def test_atomic_root_rotation_failure_and_actual_backup_restore(vault, tmp_path, monkeypatch):
    import backend.keyservice.store as module

    store, secret = vault
    store.unseal(secret, "custodian")
    org, key, context = provision(store)
    dek = secrets.token_bytes(32)
    envelope = store.wrap(org, context, dek, key["id"], "worker")
    backup = tmp_path / "backup.sqlite3"
    store.backup(backup)
    old_id = store.root_id
    original = module.protect
    count = 0

    def interrupted(*args):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("Injected failure after record re-protection, before root commit")
        return original(*args)

    monkeypatch.setattr(module, "protect", interrupted)
    with pytest.raises(OSError):
        store.rotate_root(secrets.token_bytes(32), old_id, "custodian")
    assert store.root_id == old_id
    store.seal("custodian")
    store.unseal(secret, "custodian")
    assert store.unwrap(org, context, envelope, "worker") == dek
    monkeypatch.setattr(module, "protect", original)
    replacement_secret = secrets.token_bytes(32)
    store.rotate_root(replacement_secret, old_id, "custodian")
    store.seal("custodian")
    with pytest.raises(InvalidTag):
        store.unseal(secret, "custodian")
    store.unseal(replacement_secret, "custodian")
    assert store.unwrap(org, context, envelope, "worker") == dek
    restored = KeyStore(backup)
    restored.unseal(secret, "recovery-custodian")
    assert restored.unwrap(org, context, envelope, "worker") == dek


@pytest.mark.parametrize("field", ["kem", "ephemeral", "wrap_nonce", "key", "suite", "v"])
def test_malformed_and_cross_scope_envelopes(vault, field):
    store, secret = vault
    store.unseal(secret, "custodian")
    org, key, context = provision(store)
    wrapper = store.wrap(org, context, secrets.token_bytes(32), key["id"], "worker")
    with pytest.raises(ValueError):
        store.unwrap(str(uuid.uuid4()), context, wrapper, "worker")
    with pytest.raises(InvalidTag):
        store.unwrap(org, context + "-other", wrapper, "worker")
    wrapper[field] = "unsupported"
    with pytest.raises(ValueError):
        store.unwrap(org, context, wrapper, "worker")


def certificates(tmp_path):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic key-service test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    result = {"ca": ca_path}
    for label in ["server", "custodian", "workload", "maintenance"]:
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH
                        if label == "server"
                        else ExtendedKeyUsageOID.CLIENT_AUTH
                    ]
                ),
                critical=False,
            )
        )
        if label == "server":
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
            )
        cert = builder.sign(ca_key, hashes.SHA256())
        cert_path, key_path = tmp_path / f"{label}.pem", tmp_path / f"{label}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        result[label] = (
            cert_path,
            key_path,
            hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        )
    return result


@pytest.fixture
def live_service(vault, tmp_path, settings):
    require_pq = os.environ.get("RUN_PQ_TRANSPORT") == "1"
    settings.PQ_TRANSPORT_REQUIRED = require_pq
    store, secret = vault
    certs = certificates(tmp_path)
    org = str(uuid.uuid4())
    password = secrets.token_urlsafe(24)
    identities = {
        certs["custodian"][2]: {
            "name": "custodian",
            "role": "custodian",
            "expires_at": time.time() + 3600,
            "operations": ["custody-status", "unseal", "seal", "rotate-root"],
            "password_hash": PasswordHasher().hash(password),
            "organizations": [],
        },
        certs["workload"][2]: {
            "name": "web",
            "role": "workload",
            "expires_at": time.time() + 3600,
            "operations": ["status", "versions", "wrap", "unwrap", "rewrap"],
            "organizations": [org],
        },
        certs["maintenance"][2]: {
            "name": "maintenance",
            "role": "maintenance",
            "expires_at": time.time() + 3600,
            "operations": ["versions", "rotate", "import"],
            "organizations": [org],
        },
    }
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"identities": identities}))
    service = Service(store, policy, "https://localhost:8443")
    service.accounts.create("custodian", "Test custodian", password)
    import base64
    import sqlite3
    from contextlib import closing

    with closing(sqlite3.connect(service.accounts.path)) as db, db:
        db.execute("UPDATE accounts SET password_setup=0")

    enrollment = service.accounts.login("custodian", password, "")
    totp_seed = base64.b32decode(enrollment["secret"])
    server = Server(
        ("127.0.0.1", 0),
        service,
        tls_context(str(certs["server"][0]), str(certs["server"][1]), str(certs["ca"])),
        require_pq=require_pq,
    )
    origin = f"https://localhost:{server.server_port}"
    service.origin = origin
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield {
        "store": store,
        "secret": secret,
        "certs": certs,
        "org": org,
        "password": password,
        "origin": origin,
        "port": server.server_port,
        "policy": policy,
        "service": service,
        "totp_seed": totp_seed,
        "server": server,
        "require_pq": require_pq,
    }
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def client(live, role):
    return Client(
        live["origin"],
        str(live["certs"]["ca"]),
        str(live["certs"][role][0]),
        str(live["certs"][role][1]),
        require_pq=live["require_pq"],
    )


def wait_for_connections(server, peer, count, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with server.connection_lock:
            if server.connections_by_ip.get(peer, 0) == count:
                return
        time.sleep(0.01)
    raise AssertionError("Connection admission count did not settle")


def test_idle_handshakes_are_limited_per_ip_and_release_slots(live_service):
    live = live_service
    server = live["server"]
    sockets = []
    try:
        for _ in range(4):
            sockets.append(socket.create_connection(("127.0.0.1", live["port"])))
        wait_for_connections(server, "127.0.0.1", 4)
        extra = socket.create_connection(("127.0.0.1", live["port"]))
        sockets.append(extra)
        extra.settimeout(1)
        try:
            assert extra.recv(1) == b""
        except ConnectionResetError:
            pass
        # A different immediate peer can still authenticate while the first is full.
        conn = http.client.HTTPSConnection(
            "localhost",
            live["port"],
            context=client(live, "workload").tls,
            source_address=("127.0.0.2", 0),
            timeout=1,
        )
        try:
            conn.request(
                "POST", "/v1/status", body=b"{}", headers={"Content-Type": "application/json"}
            )
            response = conn.getresponse()
            assert response.status == 200
            response.read()
        finally:
            conn.close()
        wait_for_connections(server, "127.0.0.1", 0)
        assert client(live, "workload").call("status")["sealed"] is True
    finally:
        for connection in sockets:
            connection.close()


def test_tls_trickle_does_not_extend_total_deadline(live_service):
    live = live_service
    server = live["server"]
    server.handshake_deadline_seconds = 0.4
    conn = socket.create_connection(("127.0.0.1", live["port"]))
    try:
        wait_for_connections(server, "127.0.0.1", 1)
        started = time.monotonic()
        # Incomplete TLS record: continuous progress must not reset the deadline.
        for byte in b"\x16\x03\x03\x40\x00" + b"\x01" * 50:
            try:
                conn.sendall(bytes([byte]))
            except OSError:
                break
            time.sleep(0.04)
            with server.connection_lock:
                if not server.connections_by_ip.get("127.0.0.1"):
                    break
        wait_for_connections(server, "127.0.0.1", 0, timeout=1)
        assert time.monotonic() - started < 1.2
        assert client(live, "workload").call("status")["sealed"] is True
    finally:
        conn.close()


def test_readiness_tracks_live_seal_state(live_service, monkeypatch):
    from backend.apps.core import document_service

    live = live_service
    monkeypatch.setattr(
        document_service, "read_status", lambda: client(live, "workload").call("status")
    )
    assert not document_service.ready()
    live["store"].unseal(live["secret"], "test-custodian")
    assert document_service.ready()
    live["store"].seal("test-custodian")
    assert not document_service.ready()


def portal_request(live, path, data=None, cookie="", csrf="", origin=None, role="custodian"):
    if path == "/login" and data is not None and "code" not in data:
        from django_otp.oath import TOTP

        data = {**data, "code": f"{TOTP(live['totp_seed']).token():06d}"}
    tls = client(live, role).tls
    conn = http.client.HTTPSConnection("localhost", live["port"], context=tls, timeout=5)
    try:
        conn.request(
            "GET" if data is None else "POST",
            path,
            body=None if data is None else p.canonical(data),
            headers={
                "Content-Type": "application/json",
                "Origin": origin or live["origin"],
                "Cookie": cookie,
                "X-CSRFToken": csrf,
            },
        )
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def test_real_https_portal_authentication_unseal_and_runtime_boundary(live_service):
    live = live_service
    assert client(live, "workload").call("status")["sealed"]
    status, headers, html = portal_request(live, "/")
    assert status == 200 and b"Custodian sign in" in html
    assert headers["Cache-Control"] == "no-store"
    assert portal_request(live, "/", role="workload")[0] == 403
    assert portal_request(live, "/v1/unseal", {"secret": p.encode(live["secret"])})[0] == 403
    status, headers, body = portal_request(
        live, "/login", {"username": "custodian", "password": live["password"]}
    )
    assert status == 200
    cookie, csrf = headers["Set-Cookie"].split(";")[0], json.loads(body)["csrf"]
    assert "Secure" in headers["Set-Cookie"] and "HttpOnly" in headers["Set-Cookie"]
    secret = {"secret": p.encode(live["secret"])}
    assert (
        portal_request(live, "/v1/unseal", secret, cookie, csrf, origin="https://evil.test")[0]
        == 403
    )
    assert portal_request(live, "/v1/unseal", secret, cookie, "wrong")[0] == 403
    assert portal_request(live, "/v1/unseal", secret, cookie, csrf)[0] == 200
    runtime, maintenance = client(live, "workload"), client(live, "maintenance")
    with pytest.raises(ServiceUnavailable):
        runtime.call(
            "rotate", organization=live["org"], expected=None, request_id=str(uuid.uuid4())
        )
    key = maintenance.call(
        "rotate", organization=live["org"], expected=None, request_id=str(uuid.uuid4())
    )
    context = f"secure-mail:v1:organization={live['org']}:document=sara"
    dek = secrets.token_bytes(32)
    wrapper = runtime.call(
        "wrap", organization=live["org"], context=context, dek=p.encode(dek), expected=key["id"]
    )
    assert runtime.call("unwrap", organization=live["org"], context=context, wrapper=wrapper)[
        "dek"
    ] == p.encode(dek)
    with pytest.raises(ServiceUnavailable):
        runtime.call("versions", organization=str(uuid.uuid4()))
    assert portal_request(live, "/v1/seal", {}, cookie, csrf)[0] == 200
    with pytest.raises(ServiceUnavailable):
        runtime.call("unwrap", organization=live["org"], context=context, wrapper=wrapper)
    # Policy revocation invalidates an existing authenticated maintenance session.
    live["policy"].write_text('{"identities":{}}')
    assert portal_request(live, "/v1/unseal", secret, cookie, csrf)[0] == 403


def test_no_client_certificate_cannot_connect(live_service):
    live = live_service
    tls = ssl.create_default_context(cafile=str(live["certs"]["ca"]))
    conn = http.client.HTTPSConnection("localhost", live["port"], context=tls, timeout=5)
    with pytest.raises((ssl.SSLError, OSError, http.client.HTTPException)):
        conn.request("GET", "/")
        conn.getresponse()
    conn.close()


@pytest.mark.parametrize("raw", [b"[]", b'{"x":1,"x":2}', b'{"x":NaN}'])
def test_strict_wire_json(raw):
    with pytest.raises(ValueError):
        strict_json(raw)


@pytest.mark.django_db
def test_django_service_integration_and_local_import(live_service, settings, monkeypatch, org):
    from backend.apps.core import crypto, keyring
    from backend.apps.core.models import WrappingKeyVersion

    monkeypatch.delenv("KEY_SERVICE_ALLOW_SYNTHETIC_IMPORT", raising=False)
    with pytest.raises(ServiceUnavailable):
        client(live_service, "maintenance").call(
            "import",
            organization=live_service["org"],
            key_id=str(uuid.uuid4()),
            private=p.encode(p.generate()),
        )
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SYNTHETIC_MODE", "true")
    monkeypatch.setenv("KEY_SERVICE_ALLOW_SYNTHETIC_IMPORT", "true")
    live = live_service
    ctx = crypto.context(org.pk, "document", "sara")
    original = crypto.encrypt(b"Retained synthetic document", ctx)
    local = WrappingKeyVersion.objects.get(organization=org)
    pq, classical = keyring.private_keys(local)
    live["store"].unseal(live["secret"], "test-custodian")
    policy = json.loads(live["policy"].read_text())
    for entry in policy["identities"].values():
        if entry["role"] != "custodian":
            entry["organizations"].append(str(org.pk))
    live["policy"].write_text(json.dumps(policy))
    maintenance = client(live, "maintenance")
    maintenance.call(
        "import",
        organization=str(org.pk),
        key_id=str(local.pk),
        private=p.encode(pq.private_bytes_raw() + classical.private_bytes_raw()),
    )
    settings.KEY_PROTECTOR = "key-service"
    settings.KEY_SERVICE_URL = live["origin"]
    settings.KEY_SERVICE_CA = str(live["certs"]["ca"])
    settings.KEY_SERVICE_CERT = str(live["certs"]["maintenance"][0])
    settings.KEY_SERVICE_KEY = str(live["certs"]["maintenance"][1])
    new = keyring.rotate(org, request_id=str(uuid.uuid4()), expected_active=None)
    settings.KEY_SERVICE_CERT = str(live["certs"]["workload"][0])
    settings.KEY_SERVICE_KEY = str(live["certs"]["workload"][1])

    def forbidden(*args):
        raise AssertionError("Web process must not recover persistent private keys")

    monkeypatch.setattr(keyring, "private_keys", forbidden)
    assert crypto.decrypt(original, ctx) == b"Retained synthetic document"
    value = crypto.encrypt(b"New synthetic document", ctx)
    assert crypto.decrypt(value, ctx) == b"New synthetic document"
    changed = json.loads(crypto.rewrap(original, ctx))
    assert changed["key_id"] == str(new.pk)
    assert changed["data"] == json.loads(original)["data"]
    assert crypto.decrypt(json.dumps(changed), ctx) == b"Retained synthetic document"
    assert json.loads(new.private_ciphertext)["provider"] == "key-service"
    # A sealed service must not cause Django to use local private keys or create
    # a weaker envelope. Unsealing restores reads of exactly the same ciphertext.
    live["store"].seal("test-custodian")
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(value, ctx)
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.encrypt(b"Must not be stored without key protection", ctx)
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.rewrap(value, ctx)
    live["store"].unseal(live["secret"], "test-custodian")
    assert crypto.decrypt(value, ctx) == b"New synthetic document"


@pytest.mark.django_db
@pytest.mark.parametrize("preserve_legacy", [False, True])
def test_custody_cutover_preserves_mfa_and_downloads_fail_closed(
    live_service, settings, monkeypatch, staff, staff_client, preserve_legacy
):
    from datetime import timedelta

    from django.utils import timezone

    from backend.apps.core import crypto, custody_migration, keyring, storage
    from backend.apps.core.conversations import attachment_context, message_context, subject_context
    from backend.apps.core.models import Attachment, Conversation, Message, WrappingKeyVersion

    live = live_service
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SYNTHETIC_MODE", "true")
    monkeypatch.setenv("KEY_SERVICE_ALLOW_SYNTHETIC_IMPORT", "true")
    policy = json.loads(live["policy"].read_text())
    for entry in policy["identities"].values():
        if entry["role"] != "custodian":
            entry["organizations"].append(str(staff.organization_id))
    live["policy"].write_text(json.dumps(policy))
    live["store"].unseal(live["secret"], "test")
    conversation = Conversation(
        organization=staff.organization, owner=staff, expires_at=timezone.now() + timedelta(days=7)
    )
    conversation.subject_ciphertext = crypto.encrypt(b"Subject", subject_context(conversation))
    conversation.save()
    message = Message(conversation=conversation, staff=staff)
    message.body_ciphertext = crypto.encrypt(b"Body", message_context(message))
    message.save()
    legacy = None
    if preserve_legacy:
        legacy = Message(conversation=conversation, staff=staff)
        old = json.loads(crypto.encrypt(b"Legacy", message_context(legacy)))
        old.pop("auth")
        old.pop("auth_v")
        legacy.body_ciphertext = json.dumps(old)
        legacy.save()
    attachment = Attachment(
        organization=staff.organization,
        message=message,
        state="available",
        object_key="test-object",
        size=12,
    )
    attachment.name_ciphertext = crypto.encrypt(
        b"test.txt", crypto.context(staff.organization_id, "filename", attachment.pk)
    )
    original = crypto.encrypt(b"private file", attachment_context(attachment))
    storage.put(attachment.object_key, original.encode())
    attachment.save()
    mfa_context = crypto.context(staff.organization_id, "mfa", staff.pk)
    staff.mfa_secret = crypto.encrypt(b"unchanged MFA seed", mfa_context)
    old_mfa = json.loads(staff.mfa_secret)
    staff.save(update_fields=["mfa_secret"])
    report = custody_migration.migrate(
        staff.organization,
        client(live, "maintenance"),
        client(live, "workload"),
        preserve_legacy=preserve_legacy,
    )
    assert report["verified_envelopes"] == 5
    assert len(report["preserved_unreadable_legacy"]) == int(preserve_legacy)
    if legacy:
        legacy.refresh_from_db()
        assert json.loads(legacy.body_ciphertext) == old
    assert storage.get(attachment.object_key) == original.encode()
    staff.refresh_from_db()
    assert json.loads(staff.mfa_secret)["data"] == old_mfa["data"]
    assert all(
        json.loads(row.private_ciphertext)["provider"] == "key-service"
        for row in WrappingKeyVersion.objects.all()
    )
    settings.KEY_PROTECTOR = "key-service"
    monkeypatch.setattr(keyring, "service", lambda: client(live, "workload"))

    def forbidden(*args):
        raise AssertionError("No local key fallback")

    monkeypatch.setattr(keyring, "private_keys", forbidden)
    assert crypto.decrypt(staff.mfa_secret, mfa_context) == b"unchanged MFA seed"
    url = f"/api/attachments/{attachment.pk}"
    assert staff_client.get(url).content == b"private file"
    live["store"].seal("test")
    assert staff_client.get(url).status_code == 503
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(original, attachment_context(attachment))
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt_many([(original, attachment_context(attachment))])
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(staff.mfa_secret, mfa_context)
    live["store"].unseal(live["secret"], "test")
    assert staff_client.get(url).content == b"private file"


@pytest.mark.django_db
def test_custody_migration_rejects_corruption_before_remote_mutation(org):
    from unittest.mock import Mock

    from backend.apps.core import crypto, custody_migration
    from backend.apps.core.models import StaffUser

    user = StaffUser.objects.create(username="migration-test", organization=org)
    context = crypto.context(org.pk, "mfa", user.pk)
    original = json.loads(crypto.encrypt(b"original", context))
    original["data"] = p.encode(b"corrupted ciphertext")
    user.mfa_secret = json.dumps(original)
    user.save(update_fields=["mfa_secret"])
    maintenance, workload = Mock(), Mock()
    with pytest.raises(crypto.CryptoUnavailable):
        custody_migration.migrate(org, maintenance, workload, preserve_legacy=True)
    maintenance.call.assert_not_called()
    workload.call.assert_not_called()
    user.refresh_from_db()
    assert json.loads(user.mfa_secret) == original


def test_persistent_connection_checks_seal_and_revocation(live_service):
    from backend.keyservice.client import ServiceUnavailable, pooled_client

    live = live_service
    cert, key, fingerprint = live["certs"]["workload"]
    runtime = pooled_client(
        live["origin"], str(live["certs"]["ca"]), str(cert), str(key), require_pq=live["require_pq"]
    )
    try:
        assert runtime.call("status")["sealed"]
        lease = runtime.clients.get_nowait()
        connection = lease.connection
        runtime.clients.put(lease)
        assert connection is not None
        assert runtime.call("status")["sealed"]
        lease = runtime.clients.get_nowait()
        assert lease.connection is connection
        runtime.clients.put(lease)
        live["store"].unseal(live["secret"], "test")
        assert not runtime.call("status")["sealed"]
        version = live["store"].rotate(live["org"], None, str(uuid.uuid4()), "test")
        context = f"secure-mail:v1:organization={live['org']}:document=pooled-seal"
        dek = secrets.token_bytes(32)
        wrapper = live["store"].wrap(live["org"], context, dek, version["id"], "test")
        payload = {"organization": live["org"], "context": context, "wrapper": wrapper}
        assert p.decode(runtime.call("unwrap", **payload)["dek"], 32) == dek
        live["store"].seal("test")
        assert runtime.call("status")["sealed"]
        with pytest.raises(ServiceUnavailable):
            runtime.call("unwrap", **payload)
        live["store"].unseal(live["secret"], "test")
        assert p.decode(runtime.call("unwrap", **payload)["dek"], 32) == dek
        policy = json.loads(live["policy"].read_text())
        del policy["identities"][fingerprint]
        live["policy"].write_text(json.dumps(policy))
        with pytest.raises(ServiceUnavailable):
            runtime.call("status")
    finally:
        runtime.close()


@pytest.mark.skipif(
    os.environ.get("RUN_KEY_SERVICE_LOAD") != "1", reason="Explicit component load drill"
)
def test_key_service_load_gate(live_service):
    """Synthetic component gate: 50 staff opens and 500 recipient opens, 50 in flight."""
    from backend.keyservice.client import pooled_client

    live = live_service
    store = live["store"]
    store.unseal(live["secret"], "load-test")
    version = store.rotate(live["org"], None, str(uuid.uuid4()), "load-test")
    items = []
    expected = []
    for i in range(61):
        context = f"secure-mail:v1:organization={live['org']}:load={i}"
        dek = secrets.token_bytes(32)
        wrapper = store.wrap(live["org"], context, dek, version["id"], "load-test")
        items.append({"context": context, "wrapper": wrapper})
        expected.append(dek)
    cert, key, _ = live["certs"]["workload"]
    runtime = pooled_client(
        live["origin"],
        str(live["certs"]["ca"]),
        str(cert),
        str(key),
        require_pq=live["require_pq"],
        timeout=30,
    )
    durations = []

    def opened(index):
        start = time.perf_counter()
        offset = 0
        for size in [25, 25, 11] if index < 50 else [3]:
            result = runtime.call(
                "unwrap-batch",
                organization=live["org"],
                items=items[offset : offset + size],
            )
            assert [p.decode(value, 32) for value in result["deks"]] == expected[
                offset : offset + size
            ]
            offset += size
        return time.perf_counter() - start

    start = time.perf_counter()
    try:
        with ThreadPoolExecutor(max_workers=50) as executor:
            durations = list(executor.map(opened, range(550)))
        elapsed = time.perf_counter() - start
        p95 = sorted(durations)[int(len(durations) * 0.95)]
        report = {
            "scope": "synthetic key-service component, not full portal or production",
            "staff_opens": 50,
            "recipient_opens": 500,
            "concurrency": 50,
            "batch_calls": 650,
            "staff_envelopes_per_open": 61,
            "recipient_envelopes_per_open": 3,
            "seconds": round(elapsed, 3),
            "p95_seconds": round(p95, 3),
            "errors": 0,
            "pq_transport": live["require_pq"],
        }
        output = Path(".runtime/key-service-load.json")
        output.parent.mkdir(exist_ok=True)
        output.write_text(json.dumps(report, indent=2))
        assert p95 < 30
        assert elapsed < 120
        with store.transaction() as db:
            store.verify_audit(db)
        store.seal("load-test")
        from backend.keyservice.client import ServiceUnavailable

        with pytest.raises(ServiceUnavailable):
            runtime.call(
                "unwrap-batch",
                organization=live["org"],
                items=items[:1],
            )
    finally:
        runtime.close()
