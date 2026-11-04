"""Start the separate synthetic key service for the Vite /maintenance/ route."""

import json
import os
import socket
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    directory = ROOT / ".runtime/maintenance"
    python = ROOT / ".runtime/pq-python315/python.exe"
    if not (directory / "policy.json").is_file() or not python.is_file():
        raise SystemExit("Initialize maintenance and provision the PQ-capable local runtime first.")
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", 8443)) == 0:
            raise SystemExit("Port 8443 is already in use; existing service preserved.")
    args = [
        str(python),
        "-m",
        "backend.keyservice",
        "serve",
        "--synthetic-only",
        "--backup-directory",
        str(ROOT / ".runtime/maintenance/key-backups"),
        "--store",
        str(directory / "store.sqlite3"),
        "--policy",
        str(directory / "policy.json"),
        "--cert",
        str(directory / "server.pem"),
        "--key",
        str(directory / "server.key"),
        "--ca",
        str(directory / ("client-ca.pem" if (directory / "client-ca.pem").exists() else "ca.pem")),
        "--host",
        "127.0.0.1",
        "--port",
        "8443",
        "--origin",
        "http://localhost:5173",
        "--allow-http-loopback-origin",
    ]
    with (directory / "service.log").open("ab") as log:
        process = subprocess.Popen(
            args,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    (directory / "process.json").write_text(json.dumps({"pid": process.pid}), encoding="utf-8")
    print("Started synthetic maintenance service; it begins sealed.")


if __name__ == "__main__":
    main()
