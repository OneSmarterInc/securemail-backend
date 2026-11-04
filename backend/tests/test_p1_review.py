import json
import secrets
import uuid
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.utils import timezone

from backend.apps.core import crypto, keyring
from backend.apps.core.models import Conversation, RecipientSession
from backend.keyservice import protocol as p
from backend.keyservice.store import KeyStore
from backend.tests.test_flows import compose, recipient_access


@pytest.mark.django_db
def test_public_keys_cannot_forge_mfa_or_document(org):
    key = keyring.active_key(org.pk)
    for kind in ["mfa", "attachment"]:
        context = crypto.context(org.pk, kind, "predictable-id")
        dek = secrets.token_bytes(32)
        shared, kem = MLKEM768PublicKey.from_public_bytes(
            p.decode(key.pq_public, 1184)
        ).encapsulate()
        ephemeral = X25519PrivateKey.generate()
        sx = ephemeral.exchange(
            X25519PublicKey.from_public_bytes(p.decode(key.classical_public, 32))
        )
        header = {
            "v": 2,
            "suite": p.SUITE,
            "key_id": str(key.pk),
            "kem": p.encode(kem),
            "ephemeral": p.encode(ephemeral.public_key().public_bytes_raw()),
        }
        nonce, wrap_nonce = secrets.token_bytes(12), secrets.token_bytes(12)
        wrapped = AESGCM(p.derive(shared, sx, header, context)).encrypt(
            wrap_nonce, dek, p.canonical(header) + b"\0" + context.encode()
        )
        forged = {
            **header,
            "key": p.encode(wrapped),
            "wrap_nonce": p.encode(wrap_nonce),
            "nonce": p.encode(nonce),
            "data": p.encode(
                AESGCM(dek).encrypt(nonce, b"unscanned attacker content", context.encode())
            ),
        }
        # Old unauthenticated format and a syntactically valid fake MAC both fail.
        for authentication in [{}, {"auth_v": 1, "auth": p.encode(bytes(32))}]:
            with pytest.raises(crypto.CryptoUnavailable):
                crypto.decrypt(json.dumps({**forged, **authentication}), context)


def test_rotation_backup_restores_new_key_and_failure_rolls_back(tmp_path, monkeypatch):
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "live.sqlite3", secret, backup_directory=tmp_path / "backups"
    )
    store.unseal(secret, "custodian")
    org = str(uuid.uuid4())
    context = f"secure-mail:v1:organization={org}:file=test"
    first = store.rotate(org, None, str(uuid.uuid4()), "maintenance")
    second = store.rotate(org, first["id"], str(uuid.uuid4()), "maintenance")
    dek = secrets.token_bytes(32)
    wrapper = store.wrap(org, context, dek, second["id"], "app")
    backup = sorted(store.backup_directory.glob("*.sqlite3"))[-1]
    restored = KeyStore.restore(backup, tmp_path / "restored.sqlite3", secret)
    assert restored.status()["sealed"]
    restored.unseal(secret, "recovery-custodian")
    assert restored.unwrap(org, context, wrapper, "app") == dek
    with pytest.raises(ValueError):
        KeyStore.restore(backup, tmp_path / "restored.sqlite3", secret)

    def failed(_):
        raise OSError("backup unavailable")

    monkeypatch.setattr(store, "_checkpoint", failed)
    with pytest.raises(OSError):
        store.rotate(org, second["id"], str(uuid.uuid4()), "maintenance")
    assert store.list_versions(org, active=True)[0]["id"] == second["id"]


@pytest.mark.django_db
def test_deactivation_preserves_owner_and_blocks_recipient(staff_client, staff, admin_client):
    visitor, conversation, _, _ = recipient_access(staff_client)
    result = admin_client.post(
        f"/api/admin/accounts/{staff.pk}",
        {"action": "deactivate", "reason": "Staff leave"},
        content_type="application/json",
        HTTP_IDEMPOTENCY_KEY=str(uuid.uuid4()),
    )
    assert result.status_code == 200
    assert (
        visitor.post(
            "/api/recipient/conversation", {"body": "blocked"}, content_type="application/json"
        ).status_code
        == 404
    )
    assert staff_client.get(f"/api/conversations/{conversation.pk}").status_code in [401, 403]
    conversation.refresh_from_db()
    assert conversation.owner_id == staff.pk
    assert (
        admin_client.post(
            f"/api/admin/accounts/{staff.pk}",
            {"action": "reactivate", "reason": "Staff returned"},
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=str(uuid.uuid4()),
        ).status_code
        == 200
    )
    # Old staff sessions stay invalid even after reactivation.
    assert staff_client.get(f"/api/conversations/{conversation.pk}").status_code in [401, 403]
    from backend.tests.conftest import authenticated

    staff.refresh_from_db()
    assert not staff.has_usable_password()
    assert not staff.mfa_confirmed and not staff.mfa_secret and not staff.recovery_hashes
    assert authenticated(staff).get(f"/api/conversations/{conversation.pk}").status_code == 401
    # Model completion of fresh recovery/enrolment; retained ownership is unchanged.
    staff.set_password("Fresh-test-only-password!")
    staff.mfa_confirmed = True
    staff.save()
    assert authenticated(staff).get(f"/api/conversations/{conversation.pk}").status_code == 200


@pytest.mark.django_db
def test_recipient_activity_extends_idle_window_but_polling_does_not(staff_client):
    visitor, _, _, _ = recipient_access(staff_client)
    session = RecipientSession.objects.get()
    expires = timezone.now() + timedelta(seconds=45)
    RecipientSession.objects.filter(pk=session.pk).update(expires_at=expires)
    assert visitor.get("/api/recipient/conversation").status_code == 200
    session.refresh_from_db()
    assert session.expires_at == expires
    assert (
        visitor.post("/recipient-api/recipient/activity").status_code == 401
    )  # separate cookie boundary
    # Exercise the canonical API with the same recipient session cookie.
    visitor.cookies["recipient_sessionid"] = visitor.cookies["sessionid"].value
    assert visitor.post("/recipient-api/recipient/activity").status_code == 200
    session.refresh_from_db()
    assert session.expires_at > expires + timedelta(minutes=13)
    RecipientSession.objects.filter(pk=session.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert visitor.post("/recipient-api/recipient/activity").status_code == 401


@pytest.mark.django_db
def test_explicit_nophi_and_expected_route(staff_client, staff):
    response = compose(staff_client, mode="ordinary", body="hello", subject="Nophi in a sentence")
    assert response.status_code == 201
    assert Conversation.objects.get(pk=response.json()["id"]).protected
    staff.can_nophi = True
    staff.save()
    response = compose(
        staff_client,
        mode="ordinary",
        body="hello",
        nophi_override=True,
        nophi_acknowledged=True,
        expected_route={"protected": True, "reason": "external_recipient"},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "route_changed"
    response = compose(staff_client, mode="ordinary", body="hello", nophi_override=True)
    assert response.status_code == 400
    response = compose(
        staff_client, mode="ordinary", body="hello", nophi_override=True, nophi_acknowledged=True
    )
    assert response.status_code == 201
    assert not Conversation.objects.get(pk=response.json()["id"]).protected


@pytest.mark.django_db
def test_connection_facts_do_not_claim_unsupported_services(staff_client, settings):
    settings.CRYPTO_PROVIDER = "unsupported"
    settings.STORAGE_PROVIDER = "unsupported"
    response = staff_client.get("/api/settings")
    assert response.status_code == 200
    facts = response.json()
    assert facts["document_encryption"] is None
    assert not facts["storage_configured"]
    assert "antivirus_enabled" not in facts
