"""Isolated synthetic browser/accessibility drill; stop all owned child processes."""

import hashlib
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    (root / ".runtime").mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="browser-check-", dir=root / ".runtime"))
    setup_token, inbox_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    env = {
        **os.environ,
        "APP_ENV": "test",
        "DJANGO_READ_DOT_ENV": "false",
        "SETUP_TOKEN_SHA256": hashlib.sha256(setup_token.encode()).hexdigest(),
        "DEV_INBOX_TOKEN_SHA256": hashlib.sha256(inbox_token.encode()).hexdigest(),
        "E2E_SETUP_TOKEN": setup_token,
        "E2E_DEV_INBOX_TOKEN": inbox_token,
        "APP_RUNTIME_DIR": str(work),
        "MAIL_PROVIDER": "development",
        "ENABLE_DEV_TOOLS": "true",
        "KEY_PROTECTOR": "local-development",
        "STORAGE_PROVIDER": "local",
        "PUBLIC_URL": "http://127.0.0.1:5178",
        "API_TARGET": "http://127.0.0.1:8018",
        "CSRF_TRUSTED_ORIGINS": "http://127.0.0.1:5178",
        "E2E_URL": "http://127.0.0.1:5178",
        "E2E_ARTIFACT_DIR": str(work / "artifacts"),
    }
    env.pop("POSTGRES_HOST", None)
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node is required")
    for command in [
        [sys.executable, "scripts/init_local.py"],
        [sys.executable, "manage.py", "migrate", "--noinput"],
    ]:
        subprocess.run(command, cwd=root, env=env, check=True, stdout=subprocess.DEVNULL)
    processes, logs = [], []
    try:
        commands = [
            ([sys.executable, "manage.py", "runserver", "127.0.0.1:8018", "--noreload"], root),
            ([sys.executable, "manage.py", "runworker"], root),
            ([node, "node_modules/vite/bin/vite.js", "--port", "5178"], root / "frontend"),
        ]
        for index, (command, cwd) in enumerate(commands):
            log = (work / f"process-{index}.log").open("wb")
            logs.append(log)
            processes.append(
                subprocess.Popen(
                    command,
                    cwd=cwd,
                    env=env,
                    stdout=log,
                    stderr=log,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
            )
        deadline = time.monotonic() + 60
        while True:
            if any(p.poll() is not None for p in processes):
                raise RuntimeError(f"A test service exited; inspect {work}")
            try:
                with urllib.request.urlopen(env["E2E_URL"] + "/api/health", timeout=2) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("Test services did not become ready")
            time.sleep(0.5)
        print(f"Synthetic browser evidence: {work}", flush=True)
        return subprocess.run(
            [node, "node_modules/@playwright/test/cli.js", "test"], cwd=root / "frontend", env=env
        ).returncode
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in logs:
            log.close()


if __name__ == "__main__":
    raise SystemExit(main())
