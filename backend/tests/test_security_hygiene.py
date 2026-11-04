import hashlib
import hmac
import importlib
import secrets
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from django.contrib.auth.hashers import make_password
from django.contrib.sessions.backends.db import SessionStore
from django.test import Client

from backend.apps.core import auth, conversations, evidence_transport, integrity, smtp_settings
from backend.apps.core.models import StaffInvitation
from backend.apps.core.public_network import public_address
from backend.apps.core.services import keyed
from backend.tests.test_flows import post


@pytest.mark.django_db
def test_recovery_argon2_independent_of_django_key_and_one_use(staff, settings):
    code = secrets.token_hex(16).upper()
    staff.recovery_hashes = [make_password(code, hasher="argon2")]
    staff.save()
    settings.SECRET_KEY = secrets.token_urlsafe(48)
    assert auth.verify_factor(staff, code)
    assert staff.recovery_hashes == []
    assert not auth.verify_factor(staff, code)


@pytest.mark.django_db
def test_migrated_legacy_codes_cost_argon2_and_support_explicit_old_key(staff, settings):
    old_key = secrets.token_urlsafe(48)
    code = secrets.token_hex(6).upper()
    old = hmac.new(
        old_key.encode(), f"recovery:{staff.pk}:{code}".encode(), hashlib.sha256
    ).hexdigest()
    staff.recovery_hashes = ["legacy-argon2$" + make_password(old, hasher="argon2")]
    staff.save()
    settings.SECRET_KEY = secrets.token_urlsafe(48)
    settings.RECOVERY_LEGACY_KEYS = [old_key]
    assert auth.verify_factor(staff, code)
    assert not auth.verify_factor(staff, code)


def test_hmac_purposes_and_organization_integrity_tags_differ(settings):
    assert keyed("same", purpose="otp") != keyed("same", purpose="idempotency")
    assert integrity.tag("org-a", b"file") != integrity.tag("org-b", b"file")
    assert integrity.tag("org-a", b"file") != hashlib.sha256(b"file").hexdigest()
    settings.DOCUMENT_INTEGRITY_KEY = ""
    with pytest.raises(auth.crypto.CryptoUnavailable):
        integrity.tag("org-a", b"file")


@pytest.mark.django_db
def test_setup_bad_capability_is_throttled(client, settings, monkeypatch):
    settings.SYNTHETIC_MODE = True
    settings.SETUP_TOKEN_SHA256 = hashlib.sha256(b"test-only").hexdigest()
    from django.utils import timezone

    now = timezone.now()
    monkeypatch.setattr("backend.apps.core.services.timezone.now", lambda: now)
    for _ in range(5):
        assert post(client, "/auth/setup", {"setup_token": "wrong"}).status_code == 404
    assert post(client, "/auth/setup", {"setup_token": "wrong"}).status_code == 429


@pytest.mark.django_db
def test_recipient_logout_flushes_custom_cookie():
    session = SessionStore()
    session["marker"] = "synthetic"
    session.save()
    key = session.session_key
    visitor = Client()
    visitor.cookies["recipient_sessionid"] = key
    response = visitor.post("/recipient-api/recipient/logout", {}, content_type="application/json")
    assert response.status_code == 200
    cookie = response.cookies["recipient_sessionid"]
    assert cookie["max-age"] == 0
    assert cookie["path"] == "/recipient-api/"
    assert not SessionStore().exists(key)


def test_explicit_token_wins_over_stale_session(monkeypatch):
    grant_b = object()
    lookup = Mock(return_value=grant_b)
    monkeypatch.setattr(conversations, "token_grant", lookup)
    request = SimpleNamespace(session={"recipient_session": "grant-a-hint"})
    assert conversations.verification_grant(request, "invite-b") is grant_b
    lookup.assert_called_once_with("invite-b")


@pytest.mark.parametrize(
    "address", ["64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "::ffff:169.254.169.254", "2002:a9fe:a9fe::1"]
)
def test_transition_networks_rejected_before_socket(address, monkeypatch):
    assert not public_address(address)
    addresses = [(10, 1, 6, "", (address, 443, 0, 0))]
    monkeypatch.setattr(evidence_transport.socket, "getaddrinfo", lambda *a, **k: addresses)
    socket = Mock(side_effect=AssertionError("must not open socket"))
    monkeypatch.setattr(evidence_transport.socket, "socket", socket)
    with pytest.raises(ValueError):
        evidence_transport.PublicHTTPS("example.com").connect()
    with pytest.raises(OSError):
        smtp_settings.public_socket("example.com", 587, 5)
    socket.assert_not_called()


@pytest.mark.django_db
def test_reactivate_invalidates_old_factors_and_issues_recovery(admin_client, staff):
    staff.status = "deactivated"
    staff.mfa_secret = "old-seed"
    staff.recovery_hashes = ["old-code"]
    staff.save()
    result = post(
        admin_client,
        f"/admin/accounts/{staff.pk}",
        {"action": "reactivate", "reason": "Identity reverified"},
    )
    assert result.status_code == 200, result.content
    staff.refresh_from_db()
    assert not staff.has_usable_password()
    assert not staff.mfa_confirmed and not staff.mfa_secret and not staff.recovery_hashes
    assert (
        StaffInvitation.objects.filter(
            user=staff, purpose="password_recovery", consumed_at=None
        ).count()
        == 1
    )


@pytest.mark.django_db
def test_migration_transforms_old_recovery_verifier(staff, staff_client):
    from django.apps import apps

    from backend.apps.core import evidence
    from backend.apps.core.models import Attachment, EvidenceCapture
    from backend.tests.test_evidence import submitted

    row = submitted(staff_client)
    original_digest = hashlib.sha256(b"original bytes").hexdigest()
    Attachment.objects.filter(pk=row.pk).update(sha256=original_digest)
    EvidenceCapture.objects.filter(pk=row.evidence_capture_id).update(sha256=original_digest)
    old_verifier = "a" * 64
    staff.recovery_hashes = [old_verifier]
    staff.save()
    retired = SimpleNamespace(objects=Mock())
    registry = SimpleNamespace(
        get_model=lambda app, name: (
            retired if name == "OrganizationSMTP" else apps.get_model(app, name)
        )
    )
    importlib.import_module("backend.apps.core.migrations.0021_security_hygiene").protect_existing(
        registry, None
    )
    staff.refresh_from_db()
    row.refresh_from_db()
    assert row.sha256.startswith("h1$") and row.sha256 != original_digest
    manifest, content = evidence.read_bundle(row.evidence_capture)
    assert content == b"original bytes" and manifest["sha256"] == original_digest
    assert staff.recovery_hashes[0].startswith("legacy-argon2$argon2$")
    assert old_verifier not in staff.recovery_hashes[0]
    retired.objects.update.assert_called_once_with(
        otp_password_ciphertext="", otp_transport_revision=0
    )


def test_old_otp_and_idempotency_verifiers_remain_readable(settings):
    from backend.apps.core.services import verifier_matches

    value = "synthetic-input"
    legacy = hmac.new(settings.SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()
    assert verifier_matches(value, legacy, purpose="otp")
    assert verifier_matches(value, legacy, purpose="idempotency")
    assert not verifier_matches("other", legacy, purpose="otp")
    assert not verifier_matches(value, keyed(value, purpose="otp"), purpose="idempotency")
