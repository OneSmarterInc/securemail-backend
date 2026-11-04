"""Build images and run browser tests through nginx in an isolated Compose project."""

import hashlib
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    if not shutil.which("docker"):
        raise SystemExit("Docker with Compose is required; Vite is not a fallback")
    (root / ".runtime").mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="compose-e2e-", dir=root / ".runtime"))
    setup, inbox = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    env = {
        **os.environ,
        "APP_ENV": "test",
        "CI_DB_PASSWORD": secrets.token_urlsafe(32),
        "SETUP_TOKEN_SHA256": hashlib.sha256(setup.encode()).hexdigest(),
        "DEV_INBOX_TOKEN_SHA256": hashlib.sha256(inbox.encode()).hexdigest(),
        "E2E_SETUP_TOKEN": setup,
        "E2E_DEV_INBOX_TOKEN": inbox,
        "E2E_URL": "http://127.0.0.1:8080",
        "E2E_BROWSER": "chromium",
        "E2E_ARTIFACT_DIR": str(work / "browser"),
    }
    compose = [
        "docker",
        "compose",
        "--project-name",
        "osm-ci-" + secrets.token_hex(4),
        "--env-file",
        os.devnull,
        "-f",
        str(root / "deploy/compose.ci.yaml"),
    ]

    def run(args, **kwargs):
        return subprocess.run(args, cwd=root, env=env, check=True, **kwargs)

    try:
        run(compose + ["build", "api", "frontend"])
        run(["docker", "build", "-f", "deploy/Dockerfile.pq", "-t", "onesmarter-ci-pq", "."])
        run(["docker", "run", "--rm", "onesmarter-ci-frontend", "-t"])
        # Validate the unchanged PQ configuration with the built nginx binary.
        run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=staff.example.test",
                "-keyout",
                str(work / "portal.key"),
                "-out",
                str(work / "portal.crt"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        run(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                "0",
                "-v",
                str(work) + ":/run/pki:ro",
                "-v",
                str(root / "deploy/pq-nginx.conf") + ":/etc/nginx/conf.d/default.conf:ro",
                "onesmarter-ci-frontend",
                "-t",
            ]
        )
        run(compose + ["up", "--detach", "--wait", "--wait-timeout", "180"])
        # Prove the shipped local protector works without a remote status helper.
        run(
            compose
            + [
                "exec",
                "-T",
                "api",
                "python",
                "-c",
                "import os,json,urllib.request; "
                "assert os.environ['KEY_PROTECTOR']=='local-development'; "
                "assert not os.environ.get('KEY_STATUS_URL'); "
                "assert json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/document-service'))['ready'] is True",
            ]
        )
        # Confirm notification worker is alive before browser sends requests.
        run(
            compose
            + [
                "exec",
                "-T",
                "worker",
                "celery",
                "-A",
                "backend.config.celery",
                "inspect",
                "ping",
                "--timeout",
                "10",
            ]
        )
        return subprocess.run(
            [shutil.which("node"), "node_modules/@playwright/test/cli.js", "test"],
            cwd=root / "frontend",
            env=env,
        ).returncode
    finally:
        # Retain logs locally; never upload browser sessions or test credentials.
        with (work / "compose.log").open("wb") as stream:
            subprocess.run(
                compose + ["logs", "--no-color"],
                cwd=root,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
            )
        subprocess.run(
            compose + ["down", "--volumes", "--remove-orphans"], cwd=root, env=env, check=True
        )
        print("Disposable built-stack evidence:", work)


if __name__ == "__main__":
    sys.exit(main())
