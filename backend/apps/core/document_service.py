"""Live, fail-closed admission control for document submissions and delivery."""

import secrets

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from django.conf import settings

from backend.keyservice.client import pooled_client
from backend.keyservice.protocol import SUITE

from .crypto import CryptoUnavailable


class ServiceDisabled(Exception):
    """Internal signal to defer an outbox job before contacting the mail provider."""


def read_status() -> dict:
    if settings.KEY_PROTECTOR == "local-development":
        from . import crypto, keyring
        from .models import WrappingKeyVersion

        if not settings.SYNTHETIC_MODE:
            raise ValueError("Local key custody is synthetic-only.")
        # Read the actual file, not just the process cache. A changed/missing root
        # must not report ready while cached key material masks the problem.
        root = crypto._local_key.__wrapped__()
        if not secrets.compare_digest(root, crypto._local_key()):
            raise ValueError("Local root changed; restart after reviewing custody.")
        for key in WrappingKeyVersion.objects.filter(state="active").iterator():
            if key.suite != SUITE:
                raise ValueError("Unsupported local wrapping key.")
            keyring.private_keys(key)
        # A fresh synthetic organization provisions its first wrapping key lazily
        # in active_key() on encryption; readiness does not mutate key records.
        return {"sealed": False, "suite": SUITE}
    if settings.KEY_PROTECTOR != "key-service":
        raise ValueError("Unsupported key protector.")
    return pooled_client(
        settings.KEY_STATUS_URL,
        settings.KEY_STATUS_CA,
        settings.KEY_STATUS_CERT,
        settings.KEY_STATUS_KEY,
        require_pq=settings.KEY_STATUS_REQUIRE_PQ,
        timeout=3,
    ).call("status")


def ready() -> bool:
    try:
        status = read_status()
        return (
            isinstance(status, dict)
            and status.get("sealed") is False
            and status.get("suite") == SUITE
            and status.get("audit_integrity") not in {"failed", "unverified_override"}
        )
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        CryptoUnavailable,
        InvalidTag,
        UnsupportedAlgorithm,
    ):
        return False


def require_ready() -> None:
    from .http import Problem

    if not ready():
        raise Problem("Service is disabled.", "service_disabled", 503)
