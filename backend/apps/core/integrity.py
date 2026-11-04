"""Keyed document lookup tags; raw digests live only in encrypted manifests."""

import hashlib
import re
import secrets

from django.conf import settings
from django.utils.crypto import salted_hmac

from .crypto import CryptoUnavailable


def tag_digest(org, sha256: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{64}", sha256):
        raise ValueError("Invalid SHA-256 digest")
    if len(settings.DOCUMENT_INTEGRITY_KEY) < 32:
        raise CryptoUnavailable("Document integrity key is not configured")
    return (
        "h1$"
        + salted_hmac(
            f"onesmarter:document-integrity:{org}:v1",
            sha256,
            secret=settings.DOCUMENT_INTEGRITY_KEY,
            algorithm="sha256",
        ).hexdigest()
    )


def tag(org, content: bytes) -> str:
    return tag_digest(org, hashlib.sha256(content).hexdigest())


def matches(org, content: bytes, stored: str) -> bool:
    return secrets.compare_digest(tag(org, content), stored)
