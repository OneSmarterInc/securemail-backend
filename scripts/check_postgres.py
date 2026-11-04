"""Run concurrency checks on a fresh loopback-only PostgreSQL cluster, then stop it."""

import argparse
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-bin", type=Path, required=True)
    parser.add_argument("--port", type=int, default=55439)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    runtime = root / ".runtime"
    runtime.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="postgres-check-", dir=runtime))
    secret = secrets.token_urlsafe(32)
    password = work / "initial-password"
    password.write_text(secret, encoding="ascii")
    password.chmod(0o600)
    env = {
        **os.environ,
        "APP_ENV": "test",
        "POSTGRES_HOST": "127.0.0.1",
        "POSTGRES_PORT": str(args.port),
        "POSTGRES_USER": "readiness",
        "POSTGRES_PASSWORD": secret,
        "POSTGRES_DB": "postgres",
        "POSTGRES_TOOLS": str(args.postgres_bin),
    }
    suffix = ".exe" if os.name == "nt" else ""

    def run(tool, *params):
        subprocess.run(
            [str(args.postgres_bin / (tool + suffix)), *map(str, params)],
            check=True,
            cwd=root,
            env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )

    started = False
    try:
        run(
            "initdb",
            "-D",
            work / "data",
            "-U",
            "readiness",
            "--auth=scram-sha-256",
            "--pwfile",
            password,
            "--encoding=UTF8",
            "--locale=C",
        )
        password.unlink()
        run(
            "pg_ctl",
            "-D",
            work / "data",
            "-l",
            work / "postgres.log",
            "-o",
            f"-p {args.port} -h 127.0.0.1",
            "-w",
            "start",
        )
        started = True
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "backend/tests/test_postgres_concurrency.py",
                "-q",
                "--tb=short",
                f"--basetemp={work / 'pytest'}",
            ],
            cwd=root,
            env=env,
        )
        return result.returncode
    finally:
        password.unlink(missing_ok=True)
        if started:
            run("pg_ctl", "-D", work / "data", "-m", "fast", "-w", "stop")


if __name__ == "__main__":
    raise SystemExit(main())
