"""Install the native single-EC2 startup target; never start services or change secrets."""

import argparse
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNITS = (
    "onesmarter-keyservice.service",
    "onesmarter-api.service",
    "onesmarter-worker.service",
    "onesmarter-beat.service",
)


def unit_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*\.service", value):
        raise argparse.ArgumentTypeError("Expected a systemd service unit name")
    if value == "postgresql.service":
        raise argparse.ArgumentTypeError(
            "Select the actual PostgreSQL cluster, e.g. postgresql@17-main.service"
        )
    return value


def files_for(postgres: str, redis: str, nginx: str) -> dict[str, str]:
    for unit in (postgres, redis, nginx):
        unit_name(unit)
    dependencies = f"Requires={postgres} {redis}\nAfter={postgres} {redis}\n"
    result = {
        name: (ROOT / "deploy" / name).read_text(encoding="utf-8")
        for name in (*UNITS, "onesmarter.target")
    }
    result["onesmarter.target.d/10-local-services.conf"] = (
        f"[Unit]\nRequires={postgres} {redis} {nginx}\nAfter={postgres} {redis} {nginx}\n"
    )
    for name in UNITS:
        if name != "onesmarter-keyservice.service":
            result[f"{name}.d/10-local-services.conf"] = "[Unit]\n" + dependencies
    return result


def validate_override(content: str) -> None:
    """Reject stale account/path overrides while retaining socket-group overrides."""
    if "/opt/onesmarter" in content:
        raise ValueError("Update old /opt paths in existing override first")
    for line in content.splitlines():
        name, separator, value = line.strip().partition("=")
        if separator and name.strip() == "User" and value.strip() != "onesmarter":
            raise ValueError("All Secure Mail services must use User=onesmarter")
        if separator and name.strip() == "Group" and value.strip() == "onesmarter-key":
            raise ValueError("Replace the old onesmarter-key service group")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-unit", required=True, type=unit_name)
    parser.add_argument("--redis-unit", default="redis-server.service", type=unit_name)
    parser.add_argument("--nginx-unit", default="nginx.service", type=unit_name)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Run with sudo on the Ubuntu EC2 host")
    if not shutil.which("systemctl") or not shutil.which("systemd-analyze"):
        parser.error("systemctl and systemd-analyze are required")
    expected = Path("/var/www/securemail-backend/current")
    if ROOT.resolve() != expected.resolve():
        parser.error("Run the installer from /var/www/securemail-backend/current")
    for executable in ("python", "gunicorn", "celery"):
        if not os.access(f"/var/www/securemail-backend/venv/bin/{executable}", os.X_OK):
            parser.error(f"Missing executable in the application venv: {executable}")
    for unit in (args.postgres_unit, args.redis_unit, args.nginx_unit):
        state = subprocess.check_output(
            ["systemctl", "show", unit, "--property=LoadState", "--value"], text=True
        ).strip()
        if state != "loaded":
            parser.error(f"Install/configure the required service first: {unit} ({state})")
    destination = Path("/etc/systemd/system")
    for unit in UNITS:
        for override in (destination / f"{unit}.d").glob("*.conf"):
            try:
                validate_override(override.read_text(encoding="utf-8"))
            except ValueError as error:
                parser.error(f"{error}: {override}")
    files = files_for(args.postgres_unit, args.redis_unit, args.nginx_unit)
    backup = Path("/var/backups/onesmarter-systemd") / str(time.time_ns())
    backup.mkdir(parents=True, mode=0o700)
    previous: dict[Path, bytes | None] = {}
    try:
        for relative, content in files.items():
            target = destination / relative
            if target.is_symlink():
                raise RuntimeError(f"Refusing to replace symlink: {target}")
            previous[target] = target.read_bytes() if target.exists() else None
            if target.exists():
                copy = backup / relative
                copy.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, copy)
            target.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(content.encode("utf-8"))
            try:
                temporary.chmod(0o644)
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
        subprocess.run(
            [
                "systemd-analyze",
                "verify",
                *[str(destination / n) for n in (*UNITS, "onesmarter.target")],
            ],
            check=True,
        )
    except Exception:
        for target, content in previous.items():
            if content is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(content)
        raise
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    print(f"Installed and verified. Previous unit files: {backup}")
    print("No service was started, restarted or enabled; no environment or key file changed.")
    print("After prerequisites and migrations: sudo systemctl enable --now onesmarter.target")


if __name__ == "__main__":
    main()
