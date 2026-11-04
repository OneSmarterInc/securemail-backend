"""OSM-v2 plus mandatory auth_v=1 candidate. Independent review is still required."""

import base64
import hashlib
import hmac
import json
import re
import secrets
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SUITE = "OSM-v2-MLKEM768-X25519-HKDFSHA256-AES256GCM"
HEADER = ("v", "suite", "key_id", "kem", "ephemeral")
WRAPPER = set(HEADER) | {"wrap_nonce", "key", "auth_v", "auth"}


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def parse_object(raw: str | bytes) -> dict:
    """Reject ambiguous JSON before selecting an algorithm or contacting a key store."""

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate field.")
            value[key] = item
        return value

    def invalid_constant(_):
        raise ValueError("Invalid JSON number.")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds supported limits.") from exc
    if not isinstance(value, dict):
        raise ValueError("Expected object.")
    return value


def encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode(value: str, length: int) -> bytes:
    if not isinstance(value, str) or len(value) != 4 * ((length + 2) // 3):
        raise ValueError("Invalid encoded length.")
    raw = base64.b64decode(value, validate=True)
    if len(raw) != length or encode(raw) != value:
        raise ValueError("Invalid encoding.")
    return raw


def organization(context: str) -> str:
    if not isinstance(context, str) or len(context) > 2048:
        raise ValueError("Invalid context.")
    match = re.fullmatch(r"secure-mail:v1:organization=([0-9a-f-]{36}):[^\x00-\x1f]+", context)
    if not match or str(uuid.UUID(match[1])) != match[1]:
        raise ValueError("Invalid organization context.")
    return match[1]


def private_keys(raw: bytes):
    if len(raw) != 96:
        raise ValueError("Invalid private material.")
    return (
        MLKEM768PrivateKey.from_seed_bytes(raw[:64]),
        X25519PrivateKey.from_private_bytes(raw[64:]),
    )


def generate() -> bytes:
    return (
        MLKEM768PrivateKey.generate().private_bytes_raw()
        + X25519PrivateKey.generate().private_bytes_raw()
    )


def public(raw: bytes) -> dict:
    pq, classical = private_keys(raw)
    return {
        "pq_public": encode(pq.public_key().public_bytes_raw()),
        "classical_public": encode(classical.public_key().public_bytes_raw()),
    }


def derive(pq_secret: bytes, classical_secret: bytes, header: dict, context: str) -> bytes:
    if len(pq_secret) != 32 or len(classical_secret) != 32:
        raise ValueError("Invalid shared material.")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(canonical(header)).digest(),
        info=b"onesmarter:dek-wrap:v2\0" + context.encode(),
    ).derive(pq_secret + classical_secret)


def validate(wrapper: dict) -> None:
    if (
        not isinstance(wrapper, dict)
        or set(wrapper) != WRAPPER
        or type(wrapper["v"]) is not int
        or wrapper["v"] != 2
        or type(wrapper["auth_v"]) is not int
        or wrapper["auth_v"] != 1
        or wrapper["suite"] != SUITE
        or not isinstance(wrapper["key_id"], str)
        or str(uuid.UUID(wrapper["key_id"])) != wrapper["key_id"]
    ):
        raise ValueError("Unsupported wrapper.")
    decode(wrapper["auth"], 32)
    for field, length in {"kem": 1088, "ephemeral": 32, "wrap_nonce": 12, "key": 48}.items():
        decode(wrapper[field], length)


def wrap(dek: bytes, context: str, ident: str, raw: bytes) -> dict:
    organization(context)
    if len(dek) != 32:
        raise ValueError("Invalid DEK.")
    pq, classical = private_keys(raw)
    shared, ct = pq.public_key().encapsulate()
    ephemeral = X25519PrivateKey.generate()
    sx = ephemeral.exchange(classical.public_key())
    header = {
        "v": 2,
        "suite": SUITE,
        "key_id": str(uuid.UUID(ident)),
        "kem": encode(ct),
        "ephemeral": encode(ephemeral.public_key().public_bytes_raw()),
    }
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(derive(shared, sx, header, context)).encrypt(
        nonce, dek, canonical(header) + b"\0" + context.encode()
    )
    result = {**header, "wrap_nonce": encode(nonce), "key": encode(wrapped), "auth_v": 1}
    return {**result, "auth": encode(authenticate(result, context, raw))}


def unwrap(wrapper: dict, context: str, raw: bytes) -> bytes:
    organization(context)
    validate(wrapper)
    signed = {key: value for key, value in wrapper.items() if key != "auth"}
    if not hmac.compare_digest(decode(wrapper["auth"], 32), authenticate(signed, context, raw)):
        raise InvalidTag("Wrapper origin authentication failed.")
    pq, classical = private_keys(raw)
    shared = pq.decapsulate(decode(wrapper["kem"], 1088))
    sx = classical.exchange(X25519PublicKey.from_public_bytes(decode(wrapper["ephemeral"], 32)))
    header = {field: wrapper[field] for field in HEADER}
    return AESGCM(derive(shared, sx, header, context)).decrypt(
        decode(wrapper["wrap_nonce"], 12),
        decode(wrapper["key"], 48),
        canonical(header) + b"\0" + context.encode(),
    )


def authenticate(wrapper: dict, context: str, raw: bytes) -> bytes:
    """Domain-separated MAC secret never leaves the key-service boundary."""
    private_keys(raw)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"onesmarter:wrapper-origin:hmac-sha256:v1",
    ).derive(raw)
    return hmac.new(key, canonical(wrapper) + b"\0" + context.encode(), hashlib.sha256).digest()
