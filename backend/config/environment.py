"""Load the explicitly located local profile without overriding deployment secrets."""

import os
from pathlib import Path

from dotenv import load_dotenv


def load_environment(root: Path) -> None:
    if os.environ.get("DJANGO_READ_DOT_ENV", "true").lower() == "false":
        return
    # No parent-directory searching or variable expansion inside credentials.
    load_dotenv(root / ".env", override=False, interpolate=False, encoding="utf-8")
