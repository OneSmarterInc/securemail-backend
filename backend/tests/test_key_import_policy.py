import secrets
import uuid
from unittest.mock import Mock

import pytest

from backend.keyservice import protocol as p
from backend.keyservice.server import Service
from backend.keyservice.store import KeyStore


@pytest.mark.parametrize(
    "environment,synthetic,enabled",
    [
        (None, None, None),
        ("test", "true", None),
        ("production", "true", "true"),
        ("staging", "true", "true"),
        ("test", "false", "true"),
        ("development", None, "true"),
    ],
)
def test_import_denied_at_dispatch_and_store(
    tmp_path, monkeypatch, environment, synthetic, enabled
):
    for name, value in (
        ("APP_ENV", environment),
        ("SYNTHETIC_MODE", synthetic),
        ("KEY_SERVICE_ALLOW_SYNTHETIC_IMPORT", enabled),
    ):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    org, key_id = str(uuid.uuid4()), str(uuid.uuid4())
    identity = {
        "name": "maintenance",
        "role": "maintenance",
        "organizations": [org],
        "operations": ["import"],
    }
    mocked_store = Mock()
    service = Service(mocked_store, tmp_path / "policy", "https://localhost")
    with pytest.raises(PermissionError, match="import is disabled"):
        service.dispatch(
            "import",
            {"organization": org, "key_id": key_id, "private": "invalid-before-decoding"},
            identity,
        )
    mocked_store.import_version.assert_not_called()
    store = KeyStore.initialize(
        tmp_path / "keys.sqlite3", secrets.token_bytes(32), backup_directory=tmp_path / "backups"
    )
    original = store.path.read_bytes()
    with pytest.raises(PermissionError, match="import is disabled"):
        store.import_version(org, key_id, b"invalid-before-parsing", "maintenance")
    assert store.path.read_bytes() == original
    assert not store.backup_directory.exists()


@pytest.mark.parametrize("environment", ["development", "test"])
def test_explicit_synthetic_import_retains_scope_and_idempotency(
    tmp_path, monkeypatch, environment
):
    monkeypatch.setenv("APP_ENV", environment)
    monkeypatch.setenv("SYNTHETIC_MODE", "true")
    monkeypatch.setenv("KEY_SERVICE_ALLOW_SYNTHETIC_IMPORT", "true")
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "keys.sqlite3", secret, backup_directory=tmp_path / "backups"
    )
    store.unseal(secret, "custodian")
    service = Service(store, tmp_path / "policy", "https://localhost")
    org, key_id = str(uuid.uuid4()), str(uuid.uuid4())
    data = {"organization": org, "key_id": key_id, "private": p.encode(p.generate())}
    identity = {
        "name": "maintenance",
        "role": "maintenance",
        "organizations": [org],
        "operations": ["import"],
    }
    for denied in (
        {**identity, "role": "workload"},
        {**identity, "organizations": []},
        {**identity, "operations": []},
    ):
        with pytest.raises(PermissionError):
            service.dispatch("import", data, denied)
    result = service.dispatch("import", data, identity)
    assert result["state"] == "decrypt_only"
    assert service.dispatch("import", data, identity) == result
    monkeypatch.setenv("KEY_SERVICE_ALLOW_SYNTHETIC_IMPORT", "false")
    with pytest.raises(PermissionError):
        service.dispatch("import", data, identity)
