"""A user's groups from the issuer's userinfo endpoint, for access tokens that don't carry them.

CILogon puts the claims configured on a client (e.g. ``groups``) in the ID token and the userinfo
answer, not in its JWT access tokens. An API that receives only the access token asks userinfo with
it (OIDC Core §5.3), after `BearerTokenValidator` has accepted the token: the token itself stays
the proof of who is calling, userinfo only adds the groups.

Kept apart from `BearerTokenValidator`, which stays a local check (signature and claims): this one
makes a network call, so the app chooses when to make it (e.g. not for robots, which have no user).

- The answer is cached per token until the token expires, but never longer than `max_age`: an
  issuer setting longer access tokens must not make removed groups last longer.
- A userinfo refusal (401/403) means the issuer no longer accepts the token (revoked, or a scope
  missing): `TokenValidationError`, i.e. log in again. So does a ``sub`` that isn't the token's.
- An issuer that can't answer (network, 5xx, a body that isn't a JSON object) raises
  `UserinfoUnavailableError`: the app answers 503, never "no groups" (which reads as "not allowed")
  and never 401 (which sends a CLI to log in again for nothing). Failures aren't cached.
"""

from __future__ import annotations

import hashlib
import threading
import time
from urllib.parse import urlsplit

import requests

from ..discovery import discover
from .validator import TokenValidationError


class UserinfoUnavailableError(Exception):
    """The userinfo endpoint couldn't answer: the request can't be decided now (503), it isn't refused."""


def _origin(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return parts.scheme, parts.netloc


class UserinfoGroups:
    """Reads a user's groups from the issuer's userinfo endpoint, with a cache per access token.

    Parameters
    ----------
    issuer_url:
        The trusted issuer. Its discovery document gives the userinfo endpoint, which must be on
        the issuer's own scheme and host: the user's token is never sent anywhere else.
    groups_claim:
        The userinfo claim with the groups (default ``"groups"``).
    userinfo_endpoint:
        Explicit endpoint, skipping discovery (same origin rule).
    max_age:
        Longest time, in seconds, an answer is reused, whatever the token's lifetime.
    max_entries:
        Cache size; expired answers go first, then the oldest.
    """

    def __init__(
        self,
        issuer_url: str,
        groups_claim: str = "groups",
        *,
        userinfo_endpoint: str | None = None,
        timeout: float = 3.0,
        max_age: float = 300.0,
        max_entries: int = 1024,
    ) -> None:
        self.issuer_url = issuer_url.rstrip("/")
        self.groups_claim = groups_claim
        self.timeout = timeout
        self.max_age = max_age
        self.max_entries = max_entries
        self._endpoint = userinfo_endpoint
        self._cache: dict[str, tuple[float, list[str]]] = {}
        self._lock = threading.Lock()

    def _userinfo_endpoint(self) -> str:
        if self._endpoint is None:
            try:
                endpoint = discover(self.issuer_url, timeout=self.timeout).get("userinfo_endpoint")
            except (requests.RequestException, ValueError) as exc:
                raise UserinfoUnavailableError(f"could not discover the userinfo endpoint: {exc}") from exc
            if not endpoint:
                raise UserinfoUnavailableError("the issuer has no userinfo_endpoint")
            self._endpoint = endpoint
        if _origin(self._endpoint) != _origin(self.issuer_url):
            raise UserinfoUnavailableError(f"userinfo endpoint {self._endpoint} isn't on the issuer {self.issuer_url}")
        return self._endpoint

    def groups(self, bearer_token: str, claims: dict) -> list[str]:
        """The groups of the user of `bearer_token`, a token `BearerTokenValidator` accepted with
        `claims`. Raises `TokenValidationError` when the issuer refuses the token, and
        `UserinfoUnavailableError` when it can't answer.
        """
        key = hashlib.sha256(bearer_token.encode()).hexdigest()
        now = time.time()
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None and cached[0] > now:
                return list(cached[1])

        groups = self._fetch(bearer_token, claims.get("sub"))

        expires_at = min(float(claims.get("exp", now)), now + self.max_age)
        with self._lock:
            if len(self._cache) >= self.max_entries:
                for stale in [k for k, (until, _) in self._cache.items() if until <= now]:
                    del self._cache[stale]
            while len(self._cache) >= self.max_entries:
                del self._cache[next(iter(self._cache))]
            self._cache[key] = (expires_at, groups)
        return list(groups)

    def _fetch(self, bearer_token: str, sub) -> list[str]:
        endpoint = self._userinfo_endpoint()
        try:
            response = requests.get(
                endpoint, headers={"Authorization": f"Bearer {bearer_token}"}, timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise UserinfoUnavailableError(f"userinfo unreachable: {exc}") from exc
        if response.status_code in (401, 403):
            raise TokenValidationError(f"userinfo refused the token ({response.status_code})")
        if response.status_code != 200:
            raise UserinfoUnavailableError(f"userinfo answered {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise UserinfoUnavailableError("userinfo answer isn't JSON") from exc
        if not isinstance(body, dict):
            raise UserinfoUnavailableError("userinfo answer isn't a JSON object")
        if not sub or body.get("sub") != sub:
            raise TokenValidationError("userinfo is about another user than the token")
        groups = body.get(self.groups_claim) or []
        if not isinstance(groups, list):
            return []
        return [str(group) for group in groups]
