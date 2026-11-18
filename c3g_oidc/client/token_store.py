"""On-disk cache for OIDC tokens obtained via the device-code flow.

A plain JSON file at a caller-chosen path (see `DeviceCodeSession`) -- no Flask, no
server-side dependency. Deliberately simple: this is a cache, not a secret store. Callers are
responsible for where they point it (e.g. a path under their own config/cache dir); this class
only keeps the file owner-only.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: no lock, a concurrent refresh falls back to the token the other process saved
    fcntl = None

# Never follow a symlink planted where the store writes (0 where the flag doesn't exist)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class TokenStore:
    """A plain JSON file cache for one token, at a caller-chosen path."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()

    def load(self) -> dict | None:
        """Return the cached token dict, or None if there's nothing cached yet."""
        if not self.path.exists():
            return None
        return json.loads(self.path.read_text())

    def save(self, token: dict) -> None:
        """Persist `token` (access_token, refresh_token, expires_at, ...) to disk,
        creating parent directories as needed and restricting the file to owner-only
        read/write.
        """
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Written to a new file that is owner-only from its creation, then moved over the old one:
        # never readable by others, and a concurrent reader never sees a half-written file
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        tmp.unlink(missing_ok=True)  # left by a crashed process with the same pid
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w") as file:
                file.write(json.dumps(token))
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    @contextmanager
    def lock(self):
        """Hold an exclusive lock on the token while refreshing it, so processes sharing the
        file (commands of a cron job) refresh one at a time: the others then read the new token
        instead of sending the same refresh token again, which a rotating issuer may take for a
        stolen token. The lock is released when its process ends, even killed.
        """
        if fcntl is None:
            yield
            return
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path.with_name(f".{self.path.name}.lock"), os.O_RDWR | os.O_CREAT | _NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def clear(self) -> None:
        """Delete the cached token, if any."""
        self.path.unlink(missing_ok=True)
