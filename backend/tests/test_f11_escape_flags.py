"""CLI exceptions must fail before accessing custody files or opening listeners."""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from backend.keyservice import __main__ as cli


def serve_args(tmp_path: Path, flag: str) -> list[str]:
    return [
        "serve",
        "--store",
        str(tmp_path / "missing.sqlite3"),
        "--backup-directory",
        str(tmp_path / "backups"),
        "--policy",
        str(tmp_path / "policy.json"),
        "--cert",
        "missing.pem",
        "--key",
        "missing.key",
        "--ca",
        "missing-ca.pem",
        "--origin",
        "http://localhost:5173",
        "--synthetic-only",
        flag,
    ]


@pytest.mark.parametrize("flag", ["--allow-classical-synthetic", "--allow-http-loopback-origin"])
@pytest.mark.parametrize("app_env", [None, "production", "staging", "Development"])
def test_f11_serve_rejects_escape_flags_outside_synthetic_environment(tmp_path, flag, app_env):
    env = {**os.environ, "SYNTHETIC_MODE": "true"}
    env.pop("APP_ENV", None)
    if app_env is not None:
        env["APP_ENV"] = app_env
    result = subprocess.run(
        [sys.executable, "-m", "backend.keyservice", *serve_args(tmp_path, flag)],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 2
    assert (
        "Synthetic escape flags require APP_ENV=development or test and SYNTHETIC_MODE=true"
        in result.stderr
    )
    assert not (tmp_path / "missing.sqlite3").exists()


@pytest.mark.parametrize("flag", ["--allow-classical-synthetic", "--allow-http-loopback-origin"])
@pytest.mark.parametrize("app_env", ["development", "test"])
@pytest.mark.parametrize("synthetic", [None, "false", "1", "true"])
def test_f11_explicit_opt_in_and_warning(tmp_path, monkeypatch, capsys, flag, app_env, synthetic):
    monkeypatch.setenv("APP_ENV", app_env)
    monkeypatch.delenv("SYNTHETIC_MODE", raising=False)
    if synthetic is not None:
        monkeypatch.setenv("SYNTHETIC_MODE", synthetic)
    monkeypatch.setattr(sys, "argv", ["keyservice", *serve_args(tmp_path, flag)])
    store = Mock()
    monkeypatch.setattr(cli, "KeyStore", store)
    monkeypatch.setattr(cli, "Service", Mock())
    monkeypatch.setattr(cli, "tls_context", Mock())
    server = Mock()
    server.return_value.__enter__ = Mock(return_value=Mock())
    server.return_value.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(cli, "Server", server)
    if synthetic != "true":
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 2
        store.assert_not_called()
        server.assert_not_called()
    else:
        cli.main()
        assert (
            "WARNING: Synthetic-only security exceptions enabled: " + flag
            in capsys.readouterr().err
        )
        server.assert_called_once()


@pytest.mark.parametrize("app_env", [None, "production", "staging"])
@pytest.mark.parametrize("anchor", [False, True])
def test_non_synthetic_service_cannot_start_without_review(
    tmp_path, monkeypatch, capsys, app_env, anchor
):
    monkeypatch.delenv("APP_ENV", raising=False)
    if app_env is not None:
        monkeypatch.setenv("APP_ENV", app_env)
    args = serve_args(tmp_path, "--allow-classical-synthetic")[:-1]
    if anchor:
        args.extend(["--trusted-checkpoint", str(tmp_path / "checkpoint.json")])
    monkeypatch.setattr(sys, "argv", ["keyservice", *args])
    store, server = Mock(), Mock()
    monkeypatch.setattr(cli, "KeyStore", store)
    monkeypatch.setattr(cli, "Server", server)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    expected = "deployment remains blocked" if anchor else "--trusted-checkpoint is required"
    assert expected in capsys.readouterr().err
    store.assert_not_called()
    server.assert_not_called()
