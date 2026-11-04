import json
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from backend.apps.core import crypto, keyring
from backend.apps.core.models import AuditEvent, Organization, WrappingKeyVersion

pytestmark = pytest.mark.django_db


def test_actual_mlkem_encapsulation():
    private = MLKEM768PrivateKey.generate()
    shared, encapsulation = private.public_key().encapsulate()
    assert len(encapsulation) == 1088
    assert private.decapsulate(encapsulation) == shared
    assert (
        MLKEM768PrivateKey.from_seed_bytes(private.private_bytes_raw()).decapsulate(encapsulation)
        == shared
    )


def test_rotation_preserves_old_document_without_reencrypting(org):
    context = crypto.context(org.pk, "document", "sara")
    original = crypto.encrypt(b"Sara's synthetic document", context)
    old = json.loads(original)
    new_key = keyring.rotate(org, reason="Scheduled rotation test")
    assert WrappingKeyVersion.objects.get(pk=old["key_id"]).state == "decrypt_only"
    assert crypto.decrypt(original, context) == b"Sara's synthetic document"
    rewrapped = json.loads(crypto.rewrap(original, context))
    assert rewrapped["key_id"] == str(new_key.pk)
    assert rewrapped["data"] == old["data"]
    assert rewrapped["nonce"] == old["nonce"]
    assert rewrapped["key"] != old["key"]
    assert crypto.decrypt(json.dumps(rewrapped), context) == b"Sara's synthetic document"
    assert AuditEvent.objects.filter(action="key.version_activated").count() == 2


@pytest.mark.parametrize("field", ["kem", "ephemeral", "key", "wrap_nonce", "nonce", "data"])
def test_every_envelope_component_rejects_tampering(org, field):
    context = crypto.context(org.pk, "document", "sara")
    data = json.loads(crypto.encrypt(b"sensitive sample", context))
    modified = bytearray(crypto.unb64(data[field]))
    modified[0] ^= 1
    data[field] = crypto.b64(bytes(modified))
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(json.dumps(data), context)


def test_algorithm_downgrade_and_unknown_key_rejected(org):
    context = crypto.context(org.pk, "document", "sara")
    encrypted = crypto.encrypt(b"sample", context)
    for changes in [
        {"suite": "AES-only"},
        {"v": 1},
        {"v": True},
        {"v": 2.0},
        {"key_id": 123},
        {"key_id": "00000000-0000-0000-0000-000000000000"},
    ]:
        with pytest.raises(crypto.CryptoUnavailable):
            crypto.decrypt(json.dumps({**json.loads(encrypted), **changes}), context)


@pytest.mark.parametrize("operation", [crypto.decrypt, crypto.rewrap])
@pytest.mark.parametrize("malformed", ['{"v":1,"v":2}', '{"v":NaN}', "[]"])
def test_ambiguous_envelope_rejected_before_key_access(org, monkeypatch, operation, malformed):
    def forbidden(*args):
        raise AssertionError("Malformed envelopes must not access key material")

    monkeypatch.setattr(crypto, "unwrap", forbidden)
    with pytest.raises(crypto.CryptoUnavailable):
        operation(malformed, crypto.context(org.pk, "document", "sara"))


def test_each_encryption_uses_fresh_material(org):
    context = crypto.context(org.pk, "document", "sara")
    first = json.loads(crypto.encrypt(b"same document", context))
    second = json.loads(crypto.encrypt(b"same document", context))
    assert crypto.unwrap(first, context) != crypto.unwrap(second, context)
    for field in ("kem", "ephemeral", "wrap_nonce", "nonce", "key", "data"):
        assert first[field] != second[field]


def test_wrong_tenant_and_public_key_substitution_fail(org):
    context = crypto.context(org.pk, "document", "sara")
    encrypted = crypto.encrypt(b"sample", context)
    other = Organization.objects.create(name="Other", domain="other.test")
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(encrypted, crypto.context(other.pk, "document", "sara"))
    key = WrappingKeyVersion.objects.get(organization=org)
    key.pq_public = crypto.b64(MLKEM768PrivateKey.generate().public_key().public_bytes_raw())
    key.save()
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.encrypt(b"sample", context)


def test_root_key_loss_fails_closed_and_recovery_restores_reads(org, settings):
    context = crypto.context(org.pk, "document", "sara")
    encrypted = crypto.encrypt(b"sample", context)
    original_root = settings.LOCAL_KEY_FILE.read_text()
    settings.LOCAL_KEY_FILE.write_text(crypto.b64(secrets.token_bytes(32)))
    crypto._local_key.cache_clear()
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(encrypted, context)
    settings.LOCAL_KEY_FILE.write_text(original_root)
    crypto._local_key.cache_clear()
    assert crypto.decrypt(encrypted, context) == b"sample"


def test_legacy_synthetic_migration_preserves_content_ciphertext(org, settings):
    context = crypto.context(org.pk, "document", "legacy")
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    old = {
        "v": 1,
        "provider": "synthetic-aes256gcm",
        "key_id": "local-v1",
        "key": crypto.b64(aes_key_wrap(crypto._local_key(), data_key)),
        "nonce": crypto.b64(nonce),
        "data": crypto.b64(AESGCM(data_key).encrypt(nonce, b"legacy", context.encode())),
    }
    migrated = json.loads(crypto.rewrap(json.dumps(old), context))
    assert migrated["data"] == old["data"]
    settings.ALLOW_LEGACY_SYNTHETIC_READS = False
    assert crypto.decrypt(json.dumps(migrated), context) == b"legacy"
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(json.dumps(old), context)


def test_no_classical_fallback_when_provider_unavailable(org, settings):
    settings.CRYPTO_PROVIDER = "unknown"
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.encrypt(b"sample", crypto.context(org.pk, "document", "test"))


def test_resumable_record_migration(staff_client, org):
    from backend.apps.core.key_migration import migrate
    from backend.apps.core.models import Conversation
    from backend.tests.test_flows import compose

    created = compose(staff_client)
    obj = Conversation.objects.get(pk=created.json()["id"])
    before = json.loads(obj.subject_ciphertext)
    keyring.rotate(org)
    dry_run = migrate(org)
    assert dry_run["updated"] == 0 and dry_run["candidates"] > 0
    migrated = migrate(org, apply=True, limit=1)
    assert migrated["updated"] == 1
    obj.refresh_from_db()
    assert json.loads(obj.subject_ciphertext)["data"] == before["data"]
    assert (
        crypto.decrypt(
            obj.subject_ciphertext, crypto.context(org.pk, "conversation-subject", obj.pk)
        )
        == b"Document request"
    )
    migrate(org, apply=True)
    assert migrate(org)["candidates"] == 0


def test_removed_cloud_protector_cannot_fallback(org, settings):
    settings.KEY_PROTECTOR = "removed-provider"
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.encrypt(b"sample", crypto.context(org.pk, "document", "sara"))


@pytest.mark.parametrize("value", ["[]", "null", "{}"])
def test_malformed_envelope_fails_closed(org, value):
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(value, crypto.context(org.pk, "document", "sara"))


def test_failed_rotation_keeps_current_key_usable(org, monkeypatch):
    context = crypto.context(org.pk, "document", "sara")
    original = crypto.encrypt(b"sample", context)
    active_id = json.loads(original)["key_id"]

    def unavailable(*args, **kwargs):
        raise OSError("Synthetic root protector outage")

    monkeypatch.setattr(keyring, "protect_private", unavailable)
    with pytest.raises(OSError):
        keyring.rotate(org)
    assert str(WrappingKeyVersion.objects.get(organization=org, state="active").pk) == active_id
    assert crypto.decrypt(original, context) == b"sample"


def test_file_rewrap_preserves_bytes_and_database_pointer(org, staff_client):
    from django.core.files.uploadedfile import SimpleUploadedFile

    from backend.apps.core import storage
    from backend.apps.core.conversations import attachment_context
    from backend.apps.core.key_migration import migrate
    from backend.apps.core.models import Attachment
    from backend.tests.test_flows import post, recipient_access

    recipient, _, _, _ = recipient_access(staff_client)
    response = recipient.post(
        "/api/recipient/attachments", {"file": SimpleUploadedFile("sara.txt", b"Fictional data")}
    )
    ident = response.json()["id"]
    assert post(recipient, "/recipient/conversation", {"attachments": [ident]}).status_code == 201
    attachment = Attachment.objects.get(pk=ident)
    old_key = attachment.object_key
    old_content = json.loads(storage.get(old_key))
    keyring.rotate(org)
    migrate(org, apply=True)
    attachment.refresh_from_db()
    assert attachment.object_key != old_key
    new_content = json.loads(storage.get(attachment.object_key))
    assert old_content["data"] == new_content["data"]
    assert (
        crypto.decrypt(json.dumps(new_content), attachment_context(attachment)) == b"Fictional data"
    )
    assert storage.get(old_key)
