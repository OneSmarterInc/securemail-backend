"""Native deployment lifecycle checks; no live services or emails are started."""

import argparse
import shutil
import subprocess

import pytest

from scripts.install_systemd_stack import UNITS, files_for, unit_name, validate_override


@pytest.mark.parametrize(
    "content",
    [
        "[Service]\nUser=onesmarter-key",
        "User=root",
        "User=onesmarter",
        "User=",
        "Group=onesmarter-key",
    ],
)
def test_rejects_stale_or_privileged_service_account_overrides(content):
    with pytest.raises(ValueError):
        validate_override(content)


def test_allows_nginx_socket_group_without_changing_service_user():
    validate_override("[Service]\nUser=ubuntu\nGroup=onesmarter-web\n")


@pytest.mark.parametrize(
    "name", ["postgresql.service", "../bad.service", "a.service\nWants=bad", "x", "a;id.service"]
)
def test_rejects_invalid_or_non_cluster_unit(name):
    with pytest.raises(argparse.ArgumentTypeError):
        unit_name(name)


def test_native_stack_uses_one_account_and_preserves_custodian_unseal():
    files = files_for("postgresql@17-main.service", "redis-server.service", "nginx.service")
    target = files["onesmarter.target"]
    for name in UNITS:
        assert name in target
        unit = files[name]
        assert "PartOf=onesmarter.target" in unit
        assert "WorkingDirectory=/var/www/securemail-backend/current" in unit
        assert "/var/www/securemail-backend/venv/bin/" in unit
        assert "/opt/onesmarter" not in unit
        assert "Type=exec" in unit
        assert "User=ubuntu\n" in unit
        assert "Group=ubuntu\n" in unit
    key = files["onesmarter-keyservice.service"]
    assert "User=ubuntu\n" in key
    assert "Group=ubuntu\n" in key
    assert "--host 127.0.0.1" in key
    assert "--trusted-checkpoint" in key
    assert "--synthetic-only" not in key
    assert "--allow-classical" not in key
    assert " unseal " not in key
    assert "RECOVERY" not in key
    assert "EnvironmentFile=/etc/onesmarter-key/service.env" in key
    assert not any(
        n.startswith(("nginx.service", "redis-server.service", "postgresql@")) for n in files
    )
    for name in UNITS[1:]:
        dependencies = files[f"{name}.d/10-local-services.conf"]
        assert "Requires=postgresql@17-main.service redis-server.service" in dependencies
        assert "After=postgresql@17-main.service redis-server.service" in dependencies
        assert "User=ubuntu\n" in files[name]


@pytest.mark.skipif(not shutil.which("systemd-analyze"), reason="Linux systemd tooling required")
def test_systemd_accepts_dependency_graph(tmp_path):
    files = files_for("postgresql@17-main.service", "redis-server.service", "nginx.service")
    for relative, content in files.items():
        # Validate the real dependency graph without requiring application binaries,
        # certificates, PostgreSQL or service users to be installed on the CI host.
        lines = [
            "ExecStart=/bin/true" if line.startswith("ExecStart=") else line
            for line in content.splitlines()
            if not line.startswith(("User=", "Group=", "WorkingDirectory=", "EnvironmentFile="))
        ]
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(lines) + "\n")
    for name in ("postgresql@17-main.service", "redis-server.service", "nginx.service"):
        (tmp_path / name).write_text(
            "[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n"
        )
    result = subprocess.run(
        [
            "systemd-analyze",
            "verify",
            "--man=no",
            *map(str, tmp_path.glob("*.service")),
            str(tmp_path / "onesmarter.target"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
