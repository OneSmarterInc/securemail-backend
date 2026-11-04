"""Generate missing local Compose credentials without displaying secrets."""

import hashlib
import re
import secrets
from pathlib import Path

from dotenv import dotenv_values, set_key


def initialize(path: Path) -> bool:
    existing = dotenv_values(path, interpolate=False) if path.exists() else {}
    token = existing.get("COMPOSE_SETUP_TOKEN")
    digest = existing.get("SETUP_TOKEN_SHA256")
    if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("SETUP_TOKEN_SHA256 must be a lowercase SHA-256 hex digest")
    if token and not 32 <= len(token) <= 256:
        raise ValueError("COMPOSE_SETUP_TOKEN must contain 32 to 256 characters")
    if token and digest and hashlib.sha256(token.encode()).hexdigest() != digest:
        raise ValueError("COMPOSE_SETUP_TOKEN does not match SETUP_TOKEN_SHA256")
    updates = {}
    if not existing.get("DOCUMENT_INTEGRITY_KEY"):
        updates["DOCUMENT_INTEGRITY_KEY"] = secrets.token_urlsafe(48)
    if not existing.get("POSTGRES_PASSWORD"):
        updates["POSTGRES_PASSWORD"] = secrets.token_urlsafe(48)
    if not digest:
        token = token or secrets.token_urlsafe(48)
        updates["COMPOSE_SETUP_TOKEN"] = token
        updates["SETUP_TOKEN_SHA256"] = hashlib.sha256(token.encode()).hexdigest()
    if not updates:
        return False
    if not path.exists():
        path.touch(mode=0o600, exist_ok=False)
    for name, value in updates.items():
        set_key(path, name, value, quote_mode="always")
    path.chmod(0o600)
    return True


if __name__ == "__main__":
    path = Path(__file__).resolve().parents[1] / ".env"
    changed = initialize(path)
    print(
        "Created missing Compose credentials in .env. Use COMPOSE_SETUP_TOKEN in the setup form."
        if changed
        else "Existing credentials preserved. Use the saved setup token for first-admin setup."
    )
