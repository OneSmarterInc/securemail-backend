"""External KATs and two-direction interoperability using separate algorithms.

The test-side envelope encoder is authored here, not an independent audit.
kyber-py is educational/non-constant-time and MUST remain test-only.
"""

import base64
import json
import secrets
import uuid
from pathlib import Path

import pytest
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol import DH
from Cryptodome.Protocol.KDF import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as PrimaryHKDF
from kyber_py.ml_kem import ML_KEM_768

from backend.keyservice import protocol

VECTORS = json.loads((Path(__file__).parent / "vectors/mlkem768.json").read_text())["vectors"]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda row: "kat-" + row["count"])
def test_published_mlkem768_known_answers(vector):
    seed = bytes.fromhex(vector["d"] + vector["z"])
    key = MLKEM768PrivateKey.from_seed_bytes(seed)
    assert key.public_key().public_bytes_raw() == bytes.fromhex(vector["pk"])
    ek, dk = ML_KEM_768.key_derive(seed)
    assert ek == bytes.fromhex(vector["pk"])
    assert dk == bytes.fromhex(vector["sk"])
    for suffix in ["", "_n"]:
        ciphertext = bytes.fromhex(vector["ct" + suffix])
        expected = bytes.fromhex(vector["ss" + suffix])
        assert key.decapsulate(ciphertext) == expected
        assert ML_KEM_768.decaps(dk, ciphertext) == expected


def test_rfc7748_agreement_known_answer():
    # RFC 7748 section 6.1: Alice's private and Bob's public values.
    private = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    public = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    expected = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert (
        X25519PrivateKey.from_private_bytes(private).exchange(
            X25519PublicKey.from_public_bytes(public)
        )
        == expected
    )
    assert (
        DH.key_agreement(
            static_priv=DH.import_x25519_private_key(private),
            static_pub=DH.import_x25519_public_key(public),
            kdf=lambda value: value,
        )
        == expected
    )


def test_rfc5869_hkdf_and_aes256_gcm_known_answers():
    # RFC 5869 Appendix A.1.
    ikm, salt, info = bytes.fromhex("0b" * 22), bytes(range(13)), bytes(range(240, 250))
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    assert (
        PrimaryHKDF(algorithm=hashes.SHA256(), length=42, salt=salt, info=info).derive(ikm)
        == expected
    )
    assert HKDF(ikm, 42, salt, SHA256, context=info) == expected
    # AES-256-GCM zero-key, 96-bit zero-IV, one zero plaintext block, no AAD.
    ciphertext = AESGCM(bytes(32)).encrypt(bytes(12), bytes(16), b"")
    assert ciphertext.hex() == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"


def reference_header(value):
    # Deliberately independent serializer, not importing the production helper.
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def reference_key(s_pq, s_x, header, context):
    return HKDF(
        s_pq + s_x,
        32,
        SHA256.new(reference_header(header)).digest(),
        SHA256,
        context=b"onesmarter:dek-wrap:v2\x00" + context.encode("utf-8"),
    )


def reference_wrap(raw, ident, dek, context):
    def encode(data):
        return base64.b64encode(data).decode("ascii")

    ek, _ = ML_KEM_768.key_derive(raw[:64])
    shared, ciphertext = ML_KEM_768.encaps(ek)
    ephemeral = DH.import_x25519_private_key(secrets.token_bytes(32))
    owner = DH.import_x25519_private_key(raw[64:]).public_key()
    sx = DH.key_agreement(eph_priv=ephemeral, static_pub=owner, kdf=lambda value: value)
    header = {
        "v": 2,
        "suite": "OSM-v2-MLKEM768-X25519-HKDFSHA256-AES256GCM",
        "key_id": ident,
        "kem": encode(ciphertext),
        "ephemeral": encode(ephemeral.public_key().export_key(format="raw")),
    }
    nonce = secrets.token_bytes(12)
    cipher = AES.new(reference_key(shared, sx, header, context), AES.MODE_GCM, nonce=nonce)
    cipher.update(reference_header(header) + b"\x00" + context.encode())
    value, tag = cipher.encrypt_and_digest(dek)
    result = {**header, "wrap_nonce": encode(nonce), "key": encode(value + tag), "auth_v": 1}
    from Cryptodome.Hash import HMAC

    mac_key = HKDF(raw, 32, b"", SHA256, context=b"onesmarter:wrapper-origin:hmac-sha256:v1")
    result["auth"] = encode(
        HMAC.new(mac_key, reference_header(result) + b"\0" + context.encode(), SHA256).digest()
    )
    return result


def reference_unwrap(raw, wrapper, context):
    decode = base64.b64decode
    from Cryptodome.Hash import HMAC

    mac_key = HKDF(raw, 32, b"", SHA256, context=b"onesmarter:wrapper-origin:hmac-sha256:v1")
    signed = {k: v for k, v in wrapper.items() if k != "auth"}
    HMAC.new(mac_key, reference_header(signed) + b"\0" + context.encode(), SHA256).verify(
        decode(wrapper["auth"])
    )
    _, dk = ML_KEM_768.key_derive(raw[:64])
    shared = ML_KEM_768.decaps(dk, decode(wrapper["kem"]))
    sx = DH.key_agreement(
        static_priv=DH.import_x25519_private_key(raw[64:]),
        eph_pub=DH.import_x25519_public_key(decode(wrapper["ephemeral"])),
        kdf=lambda value: value,
    )
    header = {name: wrapper[name] for name in ("v", "suite", "key_id", "kem", "ephemeral")}
    cipher = AES.new(
        reference_key(shared, sx, header, context),
        AES.MODE_GCM,
        nonce=decode(wrapper["wrap_nonce"]),
    )
    cipher.update(reference_header(header) + b"\x00" + context.encode())
    wrapped = decode(wrapper["key"])
    return cipher.decrypt_and_verify(wrapped[:-16], wrapped[-16:])


@pytest.mark.parametrize("iteration", range(3))
def test_two_direction_hybrid_interoperability(iteration):
    raw, dek, ident = protocol.generate(), secrets.token_bytes(32), str(uuid.uuid4())
    context = f"secure-mail:v1:organization={uuid.uuid4()}:document=sara-{iteration}"
    primary = protocol.wrap(dek, context, ident, raw)
    assert reference_unwrap(raw, primary, context) == dek
    reference = reference_wrap(raw, ident, dek, context)
    assert protocol.unwrap(reference, context, raw) == dek
