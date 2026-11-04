"""Initialize a local synthetic container; never auto-initialize production."""

import os
import subprocess
import sys

if os.environ.get("APP_ENV") != "development":
    raise SystemExit("Automatic initialization is limited to synthetic development.")
subprocess.run([sys.executable, "scripts/init_local.py"], check=True)
subprocess.run([sys.executable, "manage.py", "migrate", "--noinput"], check=True)
