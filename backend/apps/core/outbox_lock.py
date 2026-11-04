"""Non-expiring batch ownership; process/connection loss releases the lock."""

import errno
import os
from contextlib import contextmanager

from django.conf import settings
from django.db import connection


@contextmanager
def outbox_lock(namespace=1):
    if connection.vendor == "postgresql":
        # Requires a direct/session-pooled connection, not transaction-mode PgBouncer.
        # No long database transaction is held around network operations.
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_lock(%s, %s)", [173529, namespace])
            acquired = cursor.fetchone()[0]
            try:
                yield acquired
            finally:
                if acquired:
                    cursor.execute("SELECT pg_advisory_unlock(%s, %s)", [173529, namespace])
        return
    if connection.vendor != "sqlite" or not settings.SYNTHETIC_MODE:
        raise RuntimeError("Outbox locking requires PostgreSQL or synthetic SQLite")
    settings.RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    # Synthetic processes must share the runtime mount. Never unlink the lock file.
    with (
        settings.RUNTIME_DIR / ("outbox.lock" if namespace == 1 else f"worker-{namespace}.lock")
    ).open("a+b") as stream:
        try:
            if os.name == "nt":
                import msvcrt

                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                raise
            yield False
            return
        yield True
