import base64
import hashlib
import json
from pathlib import Path

import pytest
from Cryptodome.Cipher import AES

from backend.apps.core import crypto, keyring
from backend.keyservice import protocol
from backend.tests.test_crypto_vectors import reference_key, reference_unwrap

VECTORS = json.loads((Path(__file__).parent / "vectors/envelope_v2.json").read_text())["vectors"]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_frozen_complete_envelope(vector, settings, monkeypatch):
    raw = bytes.fromhex(vector["synthetic_recipient_material_hex"])
    envelope = vector["envelope"]
    wrapper = {key: envelope[key] for key in protocol.WRAPPER}
    context = vector["context"]
    expected = bytes.fromhex(vector["plaintext_hex"])
    assert (
        hashlib.sha256(protocol.canonical(envelope)).hexdigest()
        == vector["canonical_envelope_sha256"]
    )
    assert protocol.unwrap(wrapper, context, raw).hex() == vector["expected_dek_hex"]
    settings.KEY_PROTECTOR = "local-development"
    monkeypatch.setattr(keyring, "get_key", lambda *_: None)
    monkeypatch.setattr(keyring, "private_keys", lambda _: protocol.private_keys(raw))
    assert crypto.decrypt(json.dumps(envelope), context) == expected
    # Separate primitive libraries, but this adapter is maintained by this team.
    reference_dek = reference_unwrap(raw, wrapper, context)
    cipher = AES.new(reference_dek, AES.MODE_GCM, nonce=base64.b64decode(envelope["nonce"]))
    cipher.update(context.encode())
    content = base64.b64decode(envelope["data"])
    assert cipher.decrypt_and_verify(content[:-16], content[-16:]) == expected
    header = {name: wrapper[name] for name in protocol.HEADER}
    assert (
        reference_key(
            bytes.fromhex(vector["expected_pq_shared_hex"]),
            bytes.fromhex(vector["expected_x_shared_hex"]),
            header,
            context,
        ).hex()
        == vector["expected_wrap_key_hex"]
    )
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(json.dumps(envelope), context + "-wrong-record")
