"""OS-held service ownership; lock files are never deleted while owners may exist."""

import os
from pathlib import Path


class StoreOwnership:
    def __init__(self, store: Path):
        resolved = store.resolve()
        path = resolved.with_name(resolved.name + ".service.lock")
        self.stream = path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt

                # Lock one byte, including on a newly created empty file.
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.stream.close()
            raise ValueError(
                "Another key service owns this store, or locking is unavailable."
            ) from exc

    def close(self):
        # Closing releases the OS lock, including after process termination.
        self.stream.close()
