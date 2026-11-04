"""Fresh-process startup checks: no cached Django settings or developer dotenv."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def run_startup(arguments, environment=None):
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "COMSPEC"}
    }
    env.update(
        DJANGO_READ_DOT_ENV="false",
        DJANGO_SECRET_KEY="synthetic-startup-test-only-secret-not-for-deployment",
    )
    env.update(environment or {})
    return subprocess.run(
        [sys.executable, *arguments], cwd=ROOT, env=env, capture_output=True, text=True, timeout=30
    )


@pytest.mark.parametrize("value", [None, "", " ", "\t"])
def test_rp01_missing_app_env_must_not_start_in_synthetic_mode(value):
    result = run_startup(
        ["-c", "import backend.config.settings"], {} if value is None else {"APP_ENV": value}
    )
    assert result.returncode != 0
    assert "ImproperlyConfigured: APP_ENV must be explicitly set" in result.stderr
    assert "Run python scripts/init_local.py" not in result.stderr


@pytest.mark.parametrize("value", ["development", "test"])
def test_rp01_explicit_synthetic_environment_can_start(value):
    result = run_startup(
        ["-c", "from backend.config import settings; print(settings.ENVIRONMENT)"],
        {"APP_ENV": value},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == value


@pytest.mark.parametrize("value", ["production", "staging", "Development"])
def test_rp01_non_synthetic_environment_still_fails_closed(value):
    result = run_startup(["-c", "import backend.config.settings"], {"APP_ENV": value})
    assert result.returncode != 0
    # Older runtimes reject mandatory PQ transport before reaching the release gate.
    assert (
        "Production is blocked" in result.stderr
        or "PQ transport requires Python 3.15+" in result.stderr
    )


@pytest.mark.parametrize("script", ["init_local.py", "container_init.py"])
def test_rp01_initializers_cannot_default_to_development(script, tmp_path):
    runtime = tmp_path / "must-not-be-created"
    result = run_startup([f"scripts/{script}"], {"APP_RUNTIME_DIR": str(runtime)})
    assert result.returncode != 0
    assert not runtime.exists()


def test_rp01_explicit_test_initializer_works(tmp_path):
    runtime = tmp_path / "synthetic-runtime"
    result = run_startup(
        ["scripts/init_local.py"], {"APP_ENV": "test", "APP_RUNTIME_DIR": str(runtime)}
    )
    assert result.returncode == 0, result.stderr
    assert (runtime / "wrapping.key").is_file()
    assert (runtime / "django.secret").is_file()
