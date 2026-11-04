"""Compatibility entry point using the standard environment configuration."""

import os
import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    if len(sys.argv) < 2:
        raise SystemExit("Specify a Django command, for example: check")
    # Django loads the private root .env; explicit process variables take precedence.
    # Do not load a second profile or copy passwords into command-line arguments.
    return subprocess.run(
        [sys.executable, str(root / "manage.py"), *sys.argv[1:]], cwd=root, env=dict(os.environ)
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
