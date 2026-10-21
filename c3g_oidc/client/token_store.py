"""On-disk cache for OIDC tokens obtained via the device-code flow.

A plain JSON file at a caller-chosen path (see `DeviceCodeSession`) -- no Flask, no
server-side dependency. Deliberately simple: this is a cache, not a secret store. Callers are
responsible for where they point it (e.g. a path under their own config/cache dir); this class
only tightens the file's permissions after writing it.
"""

from __future__ import annotations

import json
from pathlib import Path


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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(token))
        self.path.chmod(0o600)
