"""Explicit operator capabilities; never infer authorization from a proxy IP."""

import hashlib
import secrets


def operator_token_valid(value: object, expected: str) -> bool:
    return (
        isinstance(value, str)
        and 32 <= len(value) <= 256
        and len(expected) == 64
        and secrets.compare_digest(hashlib.sha256(value.encode()).hexdigest(), expected)
    )
