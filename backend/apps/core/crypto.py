"""OneSmarter envelope encryption using established cryptographic primitives.

The candidate v2 protocol requires independent review before production. Callers
must authorize access and construct trusted resource context before using it.
"""

import base64
import secrets
import uuid
from functools import lru_cache

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from backend.keyservice import protocol

from . import keyring


class CryptoUnavailable(Exception):
    pass


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


@lru_cache(maxsize=1)
def _local_key() -> bytes:
    if not settings.SYNTHETIC_MODE:
        raise CryptoUnavailable("Local keys are restricted to synthetic development.")
    key = unb64(settings.LOCAL_KEY_FILE.read_text().strip())
    if len(key) != 32:
        raise CryptoUnavailable("Invalid local key configuration.")
    return key


def organization(context: str) -> uuid.UUID:
    return uuid.UUID(protocol.organization(context))


def canonical(value: dict) -> bytes:
    return protocol.canonical(value)


def derive(pq_secret: bytes, classical_secret: bytes, header: dict, context: str) -> bytes:
    return protocol.derive(pq_secret, classical_secret, header, context)


def wrap(data_key: bytes, context: str, key) -> dict:
    if (
        key.organization_id != organization(context)
        or key.state != "active"
        or key.suite != keyring.SUITE
    ):
        raise ValueError("Unsupported wrapping-key version.")
    if settings.KEY_PROTECTOR == "key-service":
        try:
            result = keyring.service().call(
                "wrap",
                organization=str(organization(context)),
                context=context,
                dek=b64(data_key),
                expected=str(key.pk),
            )
        except (OSError, ValueError):
            keyring.clear_remote_cache()
            raise
        protocol.validate(result)
        if result["key_id"] != str(key.pk):
            raise ValueError("Unexpected remote key version.")
        return result
    pq, classical = keyring.private_keys(key)
    return protocol.wrap(
        data_key, context, str(key.pk), pq.private_bytes_raw() + classical.private_bytes_raw()
    )


def unwrap(envelope: dict, context: str) -> bytes:
    if not isinstance(envelope, dict):
        raise ValueError("An envelope must be a JSON object.")
    if type(envelope.get("v")) is not int:
        raise ValueError("Invalid envelope version.")
    if envelope.get("v") == 1:
        if (
            not settings.SYNTHETIC_MODE
            or settings.KEY_PROTECTOR != "local-development"
            or not settings.ALLOW_LEGACY_SYNTHETIC_READS
            or envelope.get("provider") != "synthetic-aes256gcm"
            or envelope.get("key_id") != "local-v1"
        ):
            raise ValueError("Legacy synthetic envelopes are disabled.")
        return aes_key_unwrap(_local_key(), unb64(envelope["key"]))
    required = protocol.WRAPPER | {"nonce", "data"}
    if set(envelope) != required or envelope["v"] != 2 or envelope["suite"] != keyring.SUITE:
        raise ValueError("Unsupported or downgraded envelope.")
    wrapper = {field: envelope[field] for field in protocol.WRAPPER}
    protocol.validate(wrapper)
    if settings.KEY_PROTECTOR == "key-service":
        result = keyring.service().call(
            "unwrap", organization=str(organization(context)), context=context, wrapper=wrapper
        )
        return protocol.decode(result["dek"], 32)
    key = keyring.get_key(organization(context), envelope["key_id"])
    pq, classical = keyring.private_keys(key)
    return protocol.unwrap(wrapper, context, pq.private_bytes_raw() + classical.private_bytes_raw())


ERRORS = (
    InvalidTag,
    InvalidUnwrap,
    UnsupportedAlgorithm,
    ValueError,
    KeyError,
    TypeError,
    OSError,
    ObjectDoesNotExist,
)


def encrypt(data: bytes, context: str) -> str:
    try:
        if settings.CRYPTO_PROVIDER != "onesmarter-hybrid-v2":
            raise ValueError("Unsupported encryption provider; no fallback is permitted.")
        key = keyring.active_key(organization(context))
        data_key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        payload = AESGCM(data_key).encrypt(nonce, data, context.encode())
        return canonical(
            {**wrap(data_key, context, key), "nonce": b64(nonce), "data": b64(payload)}
        ).decode()
    except ERRORS as exc:
        raise CryptoUnavailable("Encryption or key protection is unavailable.") from exc


def content_fields(envelope: dict) -> tuple[bytes, bytes]:
    """Validate public content encoding before requesting any decryption key."""
    nonce = protocol.decode(envelope["nonce"], 12)
    encoded = envelope["data"]
    if not isinstance(encoded, str):
        raise ValueError("Invalid content encoding.")
    data = unb64(encoded)
    if len(data) < 16 or b64(data) != encoded:
        raise ValueError("Invalid ciphertext or missing authentication tag.")
    return nonce, data


def decrypt(value: str, context: str) -> bytes:
    try:
        envelope = protocol.parse_object(value)
        nonce, data = content_fields(envelope)
        return AESGCM(unwrap(envelope, context)).decrypt(nonce, data, context.encode())
    except ERRORS as exc:
        raise CryptoUnavailable("Protected content could not be verified.") from exc


def decrypt_many(values: list[tuple[str, str]]) -> list[bytes]:
    """Request-local bulk decryption; no plaintext or DEK survives this request."""
    if settings.KEY_PROTECTOR != "key-service":
        return [decrypt(value, context) for value, context in values]
    # This cache exists only for this bulk call, never across HTTP requests.
    # Include both the authenticated context and full ciphertext in the identity.
    unique = list(dict.fromkeys(values))
    results = []
    try:
        for offset in range(0, len(unique), 25):
            batch = unique[offset : offset + 25]
            orgs = {str(organization(context)) for _, context in batch}
            if len(orgs) != 1:
                raise ValueError("Batch must have a single organization")
            envelopes = [protocol.parse_object(value) for value, _ in batch]
            contents = [content_fields(envelope) for envelope in envelopes]
            items = []
            for envelope, (_, context) in zip(envelopes, batch, strict=True):
                if set(envelope) != protocol.WRAPPER | {"nonce", "data"}:
                    raise ValueError("Unsupported envelope")
                wrapper = {field: envelope[field] for field in protocol.WRAPPER}
                protocol.validate(wrapper)
                items.append({"context": context, "wrapper": wrapper})
            response = keyring.service().call("unwrap-batch", organization=orgs.pop(), items=items)
            deks = response["deks"]
            if not isinstance(deks, list) or len(deks) != len(batch):
                raise ValueError("Invalid batch response")
            for (nonce, data), (_, context), dek in zip(contents, batch, deks, strict=True):
                results.append(
                    AESGCM(protocol.decode(dek, 32)).decrypt(nonce, data, context.encode())
                )
        decoded = dict(zip(unique, results, strict=True))
        return [decoded[item] for item in values]
    except ERRORS as exc:
        raise CryptoUnavailable("Protected content could not be verified.") from exc


def rewrap(value: str, context: str) -> str:
    """Replace the wrapped data key while preserving file ciphertext, nonce and key."""
    try:
        envelope = protocol.parse_object(value)
        nonce, data = content_fields(envelope)
        data_key = unwrap(envelope, context)
        AESGCM(data_key).decrypt(nonce, data, context.encode())
        key = keyring.active_key(organization(context))
        return canonical(
            {**wrap(data_key, context, key), "nonce": envelope["nonce"], "data": envelope["data"]}
        ).decode()
    except ERRORS as exc:
        raise CryptoUnavailable("Rewrapping failed; retain the original envelope.") from exc


def context(org, kind: str, ident) -> str:
    return f"secure-mail:v1:organization={org}:{kind}={ident}"
