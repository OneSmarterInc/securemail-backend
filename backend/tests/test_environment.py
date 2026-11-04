import hashlib

import pytest
from django.test import Client
from dotenv import dotenv_values

from backend.config.environment import load_environment
from backend.tests.test_flows import post
from scripts.init_compose import initialize


def test_env_loading_preserves_override_and_literal_secrets(tmp_path, monkeypatch):
    monkeypatch.delenv("DJANGO_READ_DOT_ENV", raising=False)
    monkeypatch.setenv("EXAMPLE_EXISTING", "process-value")
    monkeypatch.delenv("EXAMPLE_SECRET", raising=False)
    (tmp_path / ".env").write_text(
        'EXAMPLE_EXISTING=file-value\nEXAMPLE_SECRET="literal-${HOME}-#-value"\n'
    )
    load_environment(tmp_path)
    import os

    assert os.environ["EXAMPLE_EXISTING"] == "process-value"
    assert os.environ["EXAMPLE_SECRET"] == "literal-${HOME}-#-value"
    monkeypatch.delenv("EXAMPLE_SECRET")


def test_env_loading_can_be_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("DJANGO_READ_DOT_ENV", "false")
    monkeypatch.delenv("EXAMPLE_DISABLED", raising=False)
    (tmp_path / ".env").write_text("EXAMPLE_DISABLED=value\n")
    load_environment(tmp_path)
    import os

    assert "EXAMPLE_DISABLED" not in os.environ


@pytest.mark.parametrize("initial", ["", "POSTGRES_PASSWORD=\nOTHER=keep\n"])
def test_compose_init_fills_placeholder_once(tmp_path, initial):
    path = tmp_path / ".env"
    path.write_text(initial)
    assert initialize(path)
    first = path.read_bytes()
    assert len(dotenv_values(path)["POSTGRES_PASSWORD"]) >= 48
    assert not initialize(path)
    assert path.read_bytes() == first
    if initial:
        assert dotenv_values(path)["OTHER"] == "keep"


@pytest.mark.django_db
def test_compose_generated_token_bootstraps_first_admin(tmp_path, settings):
    path = tmp_path / ".env"
    path.write_text("POSTGRES_PASSWORD=existing-database-password\n")
    assert initialize(path)
    values = dotenv_values(path, interpolate=False)
    assert values["POSTGRES_PASSWORD"] == "existing-database-password"
    token = values["COMPOSE_SETUP_TOKEN"]
    assert values["SETUP_TOKEN_SHA256"] == hashlib.sha256(token.encode()).hexdigest()
    settings.SETUP_TOKEN_SHA256 = values["SETUP_TOKEN_SHA256"]
    settings.SYNTHETIC_MODE = True
    client = Client()
    body = {"email": "first@onesmarter.com", "password": "Synthetic-example-password-123!"}
    assert post(client, "/auth/setup", body).status_code == 404
    assert post(client, "/auth/setup", {**body, "setup_token": token}).status_code == 200
    assert post(client, "/auth/setup", {**body, "setup_token": token}).status_code == 409
    assert not initialize(path)


def test_compose_preserves_external_setup_hash(tmp_path):
    path = tmp_path / ".env"
    digest = hashlib.sha256(b"externally-held-token").hexdigest()
    path.write_text(f"SETUP_TOKEN_SHA256={digest}\n")
    assert initialize(path)
    values = dotenv_values(path)
    assert values["SETUP_TOKEN_SHA256"] == digest
    assert "COMPOSE_SETUP_TOKEN" not in values


@pytest.mark.parametrize("digest", ["invalid", "a" * 64])
def test_compose_rejects_invalid_or_mismatched_setup_without_writes(tmp_path, digest):
    path = tmp_path / ".env"
    path.write_text(f"COMPOSE_SETUP_TOKEN={'x' * 48}\nSETUP_TOKEN_SHA256={digest}\n")
    original = path.read_bytes()
    with pytest.raises(ValueError):
        initialize(path)
    assert path.read_bytes() == original
