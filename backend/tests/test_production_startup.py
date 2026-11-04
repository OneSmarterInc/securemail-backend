"""Production-mode acceptance on isolated test data is not deployment approval."""

import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import time

import pytest
from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured

from backend.config.production import validate_production
from backend.keyservice.client import Client, ServiceUnavailable
from backend.keyservice.store import KeyStore
from backend.tests.test_keyservice import certificates
from backend.tests.test_rp01_environment import run_startup


def production_environment(tmp_path):
    certs = certificates(tmp_path)
    return {
        "APP_ENV": "production",
        "SYNTHETIC_MODE": "false",
        "DJANGO_READ_DOT_ENV": "false",
        "DJANGO_SECRET_KEY": secrets.token_urlsafe(48),
        "DOCUMENT_INTEGRITY_KEY": secrets.token_urlsafe(48),
        "SEARCH_INDEX_KEY": secrets.token_urlsafe(48),
        "PUBLIC_URL": "https://app.example.com",
        "RECIPIENT_PUBLIC_URL": "https://app.example.com/recipient",
        "ALLOWED_HOSTS": "api.example.com",
        "CSRF_TRUSTED_ORIGINS": "https://app.example.com",
        "CORS_ALLOWED_ORIGINS": "https://app.example.com",
        "TRUSTED_PROXY_UNIX_SOCKET": "true",
        "POSTGRES_HOST": "127.0.0.1",
        "REDIS_URL": "redis://127.0.0.1:6379/0",
        "MAIL_PROVIDER": "smtp",
        "KEY_PROTECTOR": "key-service",
        "KEY_SERVICE_URL": "https://localhost:8443",
        "KEY_SERVICE_CA": str(certs["ca"]),
        "KEY_SERVICE_CERT": str(certs["workload"][0]),
        "KEY_SERVICE_KEY": str(certs["workload"][1]),
        "APP_RUNTIME_DIR": str(tmp_path / "runtime"),
        "AUDIT_BUCKET": "synthetic-test-bucket",
        "AWS_REGION": "us-east-1",
        "AUDIT_RETENTION_DAYS": "2192",
    }


@pytest.fixture
def production_config(tmp_path, settings):
    environment = production_environment(tmp_path)
    config = {
        name: getattr(django_settings, name) for name in dir(django_settings) if name.isupper()
    }
    config.update({name: value for name, value in environment.items() if name in config})
    config.update(
        SECRET_KEY=environment["DJANGO_SECRET_KEY"],
        DATABASES={"default": {"ENGINE": "django.db.backends.postgresql"}},
        CELERY_BROKER_URL=environment["REDIS_URL"],
        ALLOWED_HOSTS=["api.example.com"],
        CSRF_TRUSTED_ORIGINS=["https://app.example.com"],
        CORS_ALLOWED_ORIGINS={"https://app.example.com"},
        TRUSTED_PROXY_UNIX_SOCKET=True,
        PQ_TRANSPORT_REQUIRED=True,
        RUNTIME_DIR=tmp_path / "runtime",
        AUDIT_RETENTION_DAYS=2192,
    )
    for suffix in ("URL", "CA", "CERT", "KEY"):
        config["KEY_STATUS_" + suffix] = config["KEY_SERVICE_" + suffix]
    return config, environment


def test_complete_production_config_is_accepted(production_config):
    validate_production(*production_config)


@pytest.mark.parametrize(
    "field,value",
    [
        ("SECRET_KEY", "short"),
        ("PUBLIC_URL", "http://app.example.com"),
        ("RECIPIENT_PUBLIC_URL", "http://app.example.com/recipient"),
        ("ALLOWED_HOSTS", ["*"]),
        ("CSRF_TRUSTED_ORIGINS", ["https://*.example.com"]),
        ("KEY_SERVICE_CA", ""),
        ("KEY_STATUS_KEY", ""),
        ("MAIL_PROVIDER", "development"),
        ("TRUSTED_PROXY_UNIX_SOCKET", False),
        ("AUDIT_RETENTION_DAYS", 0),
        ("DATABASES", {"default": {"ENGINE": "django.db.backends.sqlite3"}}),
    ],
)
def test_incomplete_or_unsafe_production_config_rejected(production_config, field, value):
    config, environment = production_config
    config[field] = value
    with pytest.raises(ImproperlyConfigured, match="Production configuration invalid"):
        validate_production(config, environment)


def test_synthetic_flag_and_reused_secrets_rejected(production_config):
    config, environment = production_config
    environment["ENABLE_DEV_TOOLS"] = "true"
    config["SEARCH_INDEX_KEY"] = config["SECRET_KEY"]
    with pytest.raises(ImproperlyConfigured) as error:
        validate_production(config, environment)
    assert "ENABLE_DEV_TOOLS" in str(error.value)
    assert "must differ" in str(error.value)
    assert config["SECRET_KEY"] not in str(error.value)


@pytest.mark.skipif(not hasattr(ssl.SSLContext, "set_groups"), reason="Actual PQ runtime required")
def test_real_production_django_startup(tmp_path):
    environment = production_environment(tmp_path)
    result = run_startup(
        [
            "-c",
            "import django; django.setup(); from django.conf import settings as s; assert not s.SYNTHETIC_MODE; assert s.SESSION_COOKIE_SECURE and s.CSRF_COOKIE_SECURE and s.SECURE_SSL_REDIRECT; print('production-settings-accepted')",
        ],
        {
            **environment,
            "DJANGO_SETTINGS_MODULE": "backend.config.settings",
        },
    )
    assert result.returncode == 0, result.stderr
    assert "production-settings-accepted" in result.stdout


@pytest.mark.skipif(not hasattr(ssl.SSLContext, "set_groups"), reason="Actual PQ runtime required")
def test_real_production_keyservice_starts_sealed_with_pq_mtls(tmp_path):
    certs = certificates(tmp_path)
    store = KeyStore.initialize(tmp_path / "store.sqlite3", secrets.token_bytes(32))
    store.record_event("test-operator", "initialized")
    anchor = tmp_path / "trusted.json"
    store.export_checkpoint(anchor)
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "identities": {
                    certs["workload"][2]: {
                        "name": "test-status",
                        "role": "workload",
                        "operations": ["status"],
                        "organizations": [],
                        "expires_at": time.time() + 60,
                    }
                }
            }
        )
    )
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    args = [
        sys.executable,
        "-c",
        "import sys,runpy; sys.path.insert(0, "
        + repr(str(__import__("pathlib").Path(__file__).resolve().parents[2]))
        + "); sys.argv=sys.argv[1:]; runpy.run_module('backend.keyservice',run_name='__main__')",
        "backend.keyservice",
        "serve",
        "--store",
        str(store.path),
        "--backup-directory",
        str(tmp_path / "backups"),
        "--policy",
        str(policy),
        "--cert",
        str(certs["server"][0]),
        "--key",
        str(certs["server"][1]),
        "--ca",
        str(certs["ca"]),
        "--origin",
        "https://custody.example.com",
        "--port",
        str(port),
        "--trusted-checkpoint",
        str(anchor),
    ]
    env = {
        **os.environ,
        "APP_ENV": "production",
        "SYNTHETIC_MODE": "false",
        "KEY_SERVICE_AUDIT_CANDIDATE": "false",
    }
    with (tmp_path / "service.log").open("w") as log:
        process = subprocess.Popen(args, env=env, stdout=log, stderr=log)
        try:
            client = Client(
                f"https://localhost:{port}",
                str(certs["ca"]),
                str(certs["workload"][0]),
                str(certs["workload"][1]),
                require_pq=True,
                timeout=1,
            )
            deadline = time.monotonic() + 15
            while True:
                try:
                    assert client.call("status")["sealed"] is True
                    break
                except (OSError, ServiceUnavailable):
                    if process.poll() is not None or time.monotonic() > deadline:
                        pytest.fail("Production key service did not become reachable")
                    time.sleep(0.1)
            classical = ssl.create_default_context(cafile=str(certs["ca"]))
            classical.load_cert_chain(*certs["workload"][:2])
            classical.set_groups("X25519")
            with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
                with pytest.raises(ssl.SSLError):
                    classical.wrap_socket(raw, server_hostname="localhost")
        finally:
            process.terminate()
            process.wait(timeout=10)


@pytest.mark.parametrize("checkpoint", [None, "missing"])
def test_production_cli_requires_checkpoint(tmp_path, checkpoint):
    args = [
        "-m",
        "backend.keyservice",
        "serve",
        "--store",
        str(tmp_path / "store"),
        "--backup-directory",
        str(tmp_path / "backups"),
        "--policy",
        "missing",
        "--cert",
        "missing",
        "--key",
        "missing",
        "--ca",
        "missing",
        "--origin",
        "https://custody.example.com",
    ]
    if checkpoint:
        args += ["--trusted-checkpoint", str(tmp_path / checkpoint)]
    result = run_startup(args, {"APP_ENV": "production"})
    assert result.returncode == 2
    assert "--trusted-checkpoint" in result.stderr
    assert not (tmp_path / "store").exists()
