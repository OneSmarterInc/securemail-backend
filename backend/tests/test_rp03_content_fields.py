"""Reject malformed public content fields before accessing any key material."""

import json
from unittest.mock import Mock

import pytest

from backend.apps.core import crypto, keyring

pytestmark = pytest.mark.django_db


def reject_before_keys(org, settings, monkeypatch, operation, field, value):
    context = crypto.context(org.pk, "document", "nonce-regression")
    valid = crypto.encrypt(b"Synthetic document", context)
    envelope = json.loads(valid)
    envelope[field] = value
    malformed = json.dumps(envelope)
    unwrap = Mock(side_effect=AssertionError("Malformed content must not request a key"))
    service = Mock(side_effect=AssertionError("Malformed content must not contact the service"))
    active = Mock(side_effect=AssertionError("Malformed content must not select a wrapping key"))
    monkeypatch.setattr(crypto, "unwrap", unwrap)
    monkeypatch.setattr(keyring, "service", service)
    monkeypatch.setattr(keyring, "active_key", active)
    settings.KEY_PROTECTOR = "key-service"
    with pytest.raises(crypto.CryptoUnavailable):
        if operation == "batch":
            # A bad final item must reject the whole chunk before unwrap-batch.
            crypto.decrypt_many([(valid, context), (malformed, context)])
        else:
            getattr(crypto, operation)(malformed, context)
    unwrap.assert_not_called()
    service.assert_not_called()
    active.assert_not_called()


@pytest.mark.parametrize("operation", ["decrypt", "rewrap", "batch"])
@pytest.mark.parametrize("length", [0, 8, 11, 13, 16, 128])
def test_rp03_content_nonce_length_checked_before_unwrap(
    org, settings, monkeypatch, operation, length
):
    reject_before_keys(org, settings, monkeypatch, operation, "nonce", crypto.b64(bytes(length)))


@pytest.mark.parametrize("operation", ["decrypt", "rewrap", "batch"])
@pytest.mark.parametrize("value", [None, 12, "!" * 16, "A" * 15 + "é"])
def test_rp03_nonce_encoding_checked_before_unwrap(org, settings, monkeypatch, operation, value):
    reject_before_keys(org, settings, monkeypatch, operation, "nonce", value)


@pytest.mark.parametrize("operation", ["decrypt", "rewrap", "batch"])
@pytest.mark.parametrize(
    "value",
    [None, 16, "!invalid!", "", crypto.b64(bytes(15)), "A" * 21 + "B=="],
)
def test_rp03_ciphertext_encoding_and_tag_checked_before_unwrap(
    org, settings, monkeypatch, operation, value
):
    reject_before_keys(org, settings, monkeypatch, operation, "data", value)


def test_rp03_valid_empty_plaintext_and_rewrap_preserve_content(org):
    context = crypto.context(org.pk, "document", "empty")
    encrypted = crypto.encrypt(b"", context)
    envelope = json.loads(encrypted)
    assert len(crypto.unb64(envelope["nonce"])) == 12
    assert len(crypto.unb64(envelope["data"])) == 16
    assert crypto.decrypt(encrypted, context) == b""
    rewrapped = crypto.rewrap(encrypted, context)
    assert crypto.decrypt(rewrapped, context) == b""
    assert json.loads(rewrapped)["data"] == envelope["data"]
    assert json.loads(rewrapped)["nonce"] == envelope["nonce"]


def test_rp03_valid_empty_ciphertext_reaches_batch_service(org, settings, monkeypatch):
    context = crypto.context(org.pk, "document", "empty-batch")
    encrypted = crypto.encrypt(b"", context)
    dek = crypto.unwrap(json.loads(encrypted), context)
    remote = Mock()
    remote.call.return_value = {"deks": [crypto.b64(dek)]}
    monkeypatch.setattr(keyring, "service", lambda: remote)
    settings.KEY_PROTECTOR = "key-service"
    assert crypto.decrypt_many([(encrypted, context)]) == [b""]
    assert remote.call.call_args.args == ("unwrap-batch",)
