"""OIDC discovery: fetch an issuer's `.well-known/openid-configuration` document.

Shared by both `server/` and `client/` -- it has no Flask or joserfc dependency, so pulling
it in doesn't cost either half anything the other doesn't already need (both already depend
on `requests`).
"""

from __future__ import annotations

import requests


def discover(issuer_url: str, *, timeout: float = 5.0) -> dict:
    """Fetch and return the issuer's OIDC discovery document (RFC 8414 / OIDC Discovery).

    Raises `requests.RequestException` on any network error or non-2xx response -- callers
    are expected to handle that the same way they'd handle any other network failure talking
    to the identity provider.
    """
    url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.json()
