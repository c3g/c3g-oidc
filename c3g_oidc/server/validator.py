"""Bearer token validation for Flask apps (Tier 3b authentication).

Design (see web-app-template's for-app-developers.md): validates a request's Bearer token
against COmanage's OIDC issuer (signature, expiry, issuer, audience) and returns the groups
claim as a plain list of strings -- what an app's `before_request` hook stores on `g.groups`
for `c3g-flask-opa` to read as its groups source.

Built on `joserfc` (Authlib's JOSE library -- the successor to the now-deprecated
`authlib.jose` submodule; same author, same project family) rather than a hand-rolled
JWT/signature implementation.
"""

from __future__ import annotations

import time

import requests
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from ..discovery import discover


class TokenValidationError(Exception):
    """Raised when a Bearer token fails validation: invalid, expired, or the wrong
    issuer/audience/signature -- or when the issuer's signing keys couldn't be fetched at
    all. Callers should treat this as "reject the request" (401), never as "no groups" --
    see the fail-closed design note in CLAUDE.md.
    """


class BearerTokenValidator:
    """Validates Bearer tokens issued by a single OIDC provider (COmanage) for one app.

    Parameters
    ----------
    issuer_url:
        The OIDC issuer to trust. Tokens from any other issuer are rejected. Also used to
        discover the issuer's `jwks_uri` (via `.well-known/openid-configuration`) unless
        `jwks_uri` is given explicitly.
    audience:
        This app's expected ``aud`` claim. Tokens issued for a different app are rejected.
    groups_claim:
        Name of the token claim holding the user's group memberships. Defaults to
        ``"groups"``, matching oauth2-proxy's ``OAUTH2_PROXY_OIDC_GROUPS_CLAIM`` convention
        used elsewhere in this stack (see CLAUDE.md).
    jwks_uri:
        Explicit JWKS URL, skipping discovery. Mostly useful for tests.
    algorithms:
        Signature algorithms accepted. Defaults to ``["RS256"]`` -- COmanage's OIDCop, like
        most OIDC providers, signs with RS256. Never leave this unset when calling
        `joserfc.jwt.decode` yourself: an unrestricted algorithm list is how "alg
        confusion" signature-bypass attacks happen.
    leeway:
        Seconds of clock skew tolerated on `exp`/`nbf`/`iat` checks.
    jwks_ttl:
        Seconds to cache fetched signing keys before re-fetching. Avoids a network round
        trip to the issuer on every single request.
    """

    def __init__(
        self,
        issuer_url: str,
        audience: str,
        groups_claim: str = "groups",
        *,
        jwks_uri: str | None = None,
        algorithms: list[str] | None = None,
        leeway: int = 30,
        jwks_ttl: float = 3600.0,
        timeout: float = 5.0,
    ) -> None:
        self.issuer_url = issuer_url.rstrip("/")
        self.audience = audience
        self.groups_claim = groups_claim
        self.algorithms = algorithms or ["RS256"]
        self.leeway = leeway
        self.jwks_ttl = jwks_ttl
        self.timeout = timeout
        self._jwks_uri = jwks_uri
        self._jwks_cache: KeySet | None = None
        self._jwks_cache_at = 0.0

    def _resolve_jwks_uri(self) -> str:
        if self._jwks_uri:
            return self._jwks_uri
        metadata = discover(self.issuer_url, timeout=self.timeout)
        return metadata["jwks_uri"]

    def _get_jwks(self) -> KeySet:
        now = time.monotonic()
        if self._jwks_cache is not None and (now - self._jwks_cache_at) < self.jwks_ttl:
            return self._jwks_cache

        response = requests.get(self._resolve_jwks_uri(), timeout=self.timeout)
        response.raise_for_status()
        jwks = KeySet.import_key_set(response.json())

        self._jwks_cache = jwks
        self._jwks_cache_at = now
        return jwks

    def validate(self, bearer_token: str) -> list[str]:
        """Validate `bearer_token` and return its groups claim as a list of strings.

        Raises `TokenValidationError` on any invalid/expired/wrong-issuer/wrong-audience/
        wrong-signature token, or if the issuer's signing keys couldn't be fetched -- never
        returns an empty or partial result for a bad token. Fail closed: the caller should
        treat any exception here as "reject the request", not "no groups".
        """
        if not bearer_token:
            raise TokenValidationError("empty bearer token")

        try:
            jwks = self._get_jwks()
            token = jwt.decode(bearer_token, jwks, algorithms=self.algorithms)

            registry = JWTClaimsRegistry(
                leeway=self.leeway,
                iss={"essential": True, "value": self.issuer_url},
                aud={"essential": True, "value": self.audience},
                exp={"essential": True},
            )
            registry.validate(token.claims)
        except JoseError as exc:
            raise TokenValidationError(str(exc)) from exc
        except requests.RequestException as exc:
            raise TokenValidationError(f"could not fetch signing keys: {exc}") from exc

        groups = token.claims.get(self.groups_claim, [])
        if not isinstance(groups, list):
            return []
        return [str(group) for group in groups]
