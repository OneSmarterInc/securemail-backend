"""Application-owned key lifecycle using established library primitives.

The candidate envelope protocol requires independent review before production.
These operations are not ordinary portal-administrator endpoints.
"""

import base64
import json
import secrets
import threading
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.db import transaction

from backend.keyservice import protocol
from backend.keyservice.client import ClientPool, pooled_client

from .models import IdempotencyRecord, WrappingKeyVersion

SUITE = "OSM-v2-MLKEM768-X25519-HKDFSHA256-AES256GCM"


def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def root_context(key: WrappingKeyVersion) -> dict[str, str]:
    return {
        "application": "onesmarter-secure-mail",
        "purpose": "wrapping-private-key",
        "organization": str(key.organization_id),
        "version": str(key.pk),
        "suite": SUITE,
    }


def protect_private(data: bytes, key: WrappingKeyVersion) -> str:
    context = root_context(key)
    if settings.KEY_PROTECTOR != "local-development" or not settings.SYNTHETIC_MODE:
        raise ValueError("Approved key protector is unavailable.")
    from .crypto import _local_key

    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(_local_key()).encrypt(
        nonce, data, json.dumps(context, sort_keys=True).encode()
    )
    return json.dumps(
        {
            "provider": "local-development",
            "key_id": "local-v1",
            "nonce": encode(nonce),
            "data": encode(encrypted),
        }
    )


def private_keys(key: WrappingKeyVersion) -> tuple[MLKEM768PrivateKey, X25519PrivateKey]:
    envelope = json.loads(key.private_ciphertext)
    context = root_context(key)
    if (
        envelope["provider"] == "local-development"
        and envelope["key_id"] == "local-v1"
        and settings.KEY_PROTECTOR == "local-development"
        and settings.SYNTHETIC_MODE
    ):
        from .crypto import _local_key

        raw = AESGCM(_local_key()).decrypt(
            decode(envelope["nonce"]),
            decode(envelope["data"]),
            json.dumps(context, sort_keys=True).encode(),
        )
    else:
        raise ValueError("Unsupported key protector.")
    if len(raw) != 96:
        raise ValueError("Invalid private-key material.")
    pq = MLKEM768PrivateKey.from_seed_bytes(raw[:64])
    classical = X25519PrivateKey.from_private_bytes(raw[64:])
    if (
        encode(pq.public_key().public_bytes_raw()) != key.pq_public
        or encode(classical.public_key().public_bytes_raw()) != key.classical_public
    ):
        raise ValueError("Key metadata does not match protected material.")
    return pq, classical


@transaction.atomic
def rotate(
    org,
    *,
    actor=None,
    reason: str = "Initial key provisioning",
    request_id: str | None = None,
    expected_active: str | None = "",
) -> WrappingKeyVersion:
    from .services import audit, keyed, lock_organization, verifier_matches

    organization = lock_organization(org)
    if settings.KEY_PROTECTOR == "key-service" and (not request_id or expected_active == ""):
        raise ValueError(
            "Remote rotation requires a stable request_id and explicit expected_active (None for initial provisioning)."
        )
    record = None
    if request_id:
        request_id = str(uuid.UUID(request_id))
        fingerprint = keyed(
            json.dumps(
                {
                    "expected": expected_active,
                    "reason": reason,
                    "actor": str(getattr(actor, "pk", actor)),
                },
                sort_keys=True,
            )
        )
        record = {
            "organization": organization,
            "actor": "key-rotation",
            "operation": "rotate",
            "key": request_id,
        }
        previous = IdempotencyRecord.objects.filter(**record).first()
        if previous:
            if not verifier_matches(
                json.dumps(
                    {
                        "expected": expected_active,
                        "reason": reason,
                        "actor": str(getattr(actor, "pk", actor)),
                    },
                    sort_keys=True,
                ),
                previous.fingerprint,
                purpose="idempotency",
            ):
                raise ValueError("Rotation operation ID was reused with different parameters.")
            return WrappingKeyVersion.objects.get(
                pk=previous.resource_id, organization=organization
            )
        record["fingerprint"] = fingerprint
    if settings.KEY_PROTECTOR == "key-service":
        clear_remote_cache()
        result = service().call(
            "rotate",
            organization=str(organization.pk),
            expected=expected_active,
            request_id=request_id,
        )
        key = synchronize(result)
        audit(
            organization,
            actor,
            "key.version_activated",
            "wrapping_key",
            key.pk,
            metadata={"suite": SUITE, "reason": reason[:300]},
        )
        IdempotencyRecord.objects.create(**record, resource_id=str(key.pk))
        return key
    if expected_active != "":
        current = WrappingKeyVersion.objects.filter(
            organization=organization, state="active"
        ).first()
        if (str(current.pk) if current else None) != expected_active:
            raise ValueError("Active key changed; confirm the rotation plan.")
    pq, classical = MLKEM768PrivateKey.generate(), X25519PrivateKey.generate()
    key = WrappingKeyVersion(
        organization=organization,
        suite=SUITE,
        pq_public=encode(pq.public_key().public_bytes_raw()),
        classical_public=encode(classical.public_key().public_bytes_raw()),
    )
    key.private_ciphertext = protect_private(
        pq.private_bytes_raw() + classical.private_bytes_raw(), key
    )
    private_keys(key)
    WrappingKeyVersion.objects.filter(organization=organization, state="active").update(
        state="decrypt_only"
    )
    key.save()
    audit(
        organization,
        actor,
        "key.version_activated",
        "wrapping_key",
        key.pk,
        metadata={"suite": SUITE, "reason": reason[:300]},
    )
    if record:
        IdempotencyRecord.objects.create(**record, resource_id=str(key.pk))
    return key


def active_key(org) -> WrappingKeyVersion:
    if settings.KEY_PROTECTOR == "key-service":
        return active_remote(org)
    key = WrappingKeyVersion.objects.filter(organization_id=org, state="active").first()
    if key is None and settings.SYNTHETIC_MODE:
        from .services import lock_organization

        with transaction.atomic():
            lock_organization(org)
            key = WrappingKeyVersion.objects.filter(organization_id=org, state="active").first()
            if key is None:
                key = rotate(org)
    if key is None:
        raise ValueError("No active wrapping-key version is provisioned.")
    return key


def get_key(org, ident) -> WrappingKeyVersion:
    return WrappingKeyVersion.objects.get(
        pk=uuid.UUID(ident), organization_id=org, suite=SUITE, state__in=["active", "decrypt_only"]
    )


def service() -> ClientPool:
    return pooled_client(
        settings.KEY_SERVICE_URL,
        settings.KEY_SERVICE_CA,
        settings.KEY_SERVICE_CERT,
        settings.KEY_SERVICE_KEY,
        require_pq=settings.KEY_SERVICE_REQUIRE_PQ,
    )


@transaction.atomic
def synchronize(metadata: dict) -> WrappingKeyVersion:
    from .services import lock_organization

    if metadata["suite"] != SUITE or metadata["state"] not in {"active", "decrypt_only"}:
        raise ValueError("Unsupported remote key metadata.")
    protocol.decode(metadata["pq_public"], 1184)
    protocol.decode(metadata["classical_public"], 32)
    org = lock_organization(metadata["organization"])
    existing = WrappingKeyVersion.objects.filter(pk=metadata["id"]).first()
    if existing and (
        existing.organization_id != org.pk
        or existing.pq_public != metadata["pq_public"]
        or existing.classical_public != metadata["classical_public"]
    ):
        raise ValueError("Remote key identity mismatch.")
    if metadata["state"] == "active":
        WrappingKeyVersion.objects.filter(organization=org, state="active").exclude(
            pk=metadata["id"]
        ).update(state="decrypt_only")
    key, _ = WrappingKeyVersion.objects.update_or_create(
        pk=metadata["id"],
        defaults={
            "organization": org,
            "suite": SUITE,
            "state": metadata["state"],
            "pq_public": metadata["pq_public"],
            "classical_public": metadata["classical_public"],
            "private_ciphertext": json.dumps({"provider": "key-service", "id": metadata["id"]}),
        },
    )
    return key


_remote_cache = threading.local()


def clear_remote_cache():
    _remote_cache.entry = None


def active_remote(org, *, required=True):
    scope = str(getattr(org, "pk", org))
    identity = (
        scope,
        settings.KEY_SERVICE_URL,
        str(settings.KEY_SERVICE_CERT),
        str(settings.KEY_SERVICE_KEY),
        str(settings.KEY_SERVICE_CA),
        settings.KEY_SERVICE_REQUIRE_PQ,
    )
    cached = getattr(_remote_cache, "entry", None)
    # Only public metadata is cached. Every wrap still requires a live service
    # authorization and expected-active-version check; there is no local fallback.
    if required and cached and cached[0] == identity and time.monotonic() < cached[1]:
        return cached[2]
    versions = service().call("versions", organization=str(getattr(org, "pk", org)), active=True)[
        "versions"
    ]
    active = [item for item in versions if item["state"] == "active"]
    if len(active) > 1 or (required and not active):
        raise ValueError("No unique active service key is provisioned.")
    if active:
        if active[0]["organization"] != str(getattr(org, "pk", org)):
            raise ValueError("Wrong key scope.")
        key = synchronize(active[0])
        _remote_cache.entry = (identity, time.monotonic() + 2, key)
        return key
    return None
