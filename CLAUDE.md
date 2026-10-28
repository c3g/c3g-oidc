# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`c3g-oidc` is the in-app OpenID Connect client library for C3G apps that need **Tier 3b**
authentication — see [web-app-template](https://github.com/c3g/web-app-template)'s
`for-app-developers.md` and `README.md` for where this sits among the authentication/
authorization tiers oauth2-proxy/OPA cover. Two independent halves, each importable on its own
and gated behind its own install extra:

- `c3g_oidc/server/` — validates a Bearer token inside a Flask app.
- `c3g_oidc/client/` — device-code login (RFC 8628) plus token cache/refresh, for a
  non-browser client such as a CLI. No Flask dependency.

**Status: working, and verified for real**, not mocked out. `project_tracking` (via its
`pt_cli` companion) is the intended first consumer — see `for-app-developers.md`'s Flask
section in `web-app-template` for why `project_tracking` specifically needs the client half.

## Repo layout

```
c3g_oidc/
  discovery.py       # discover() -- shared OIDC discovery, no Flask/joserfc dependency
  server/
    validator.py      # BearerTokenValidator -- signature/expiry/issuer/audience via joserfc
    broker.py         # device_flow_broker -- forwards a CLI's device-code login with the app's secret
  client/
    device_flow.py     # DeviceCodeSession -- RFC 8628 device-code login + refresh
    client_credentials.py  # ClientCredentialsSession -- robots: client credentials grant, in-memory cache
    token_store.py       # on-disk token cache, used by device_flow
tests/
  test_server.py            # real RSA-signed JWTs against a real HTTP-served JWKS
  test_client.py             # real RFC 8628 flow against a mock authorization server
  test_client_credentials.py # robots' token requests against a mock token endpoint
  test_broker.py             # the forwarding routes against a recording mock issuer
```

## Design notes

- **Server and client must stay independent.** An app using only the server half (validating
  incoming tokens) should never need client-side dependencies (nothing that opens a browser or
  polls a device-code endpoint), and a CLI using only the client half shouldn't pull in Flask.
  Enforced via `[project.optional-dependencies]` extras in `pyproject.toml` — keep new
  dependencies in the extra that actually needs them, not the shared base list. `discovery.py`
  is the one thing both halves share, and deliberately has no Flask/joserfc dependency itself
  so sharing it doesn't violate this.
- **Fail closed.** `BearerTokenValidator.validate()` raises on any invalid, expired,
  wrong-audience, wrong-issuer, or wrong-signature token — including one signed by a key not
  in the issuer's published JWKS — never returns an empty groups list silently. The caller (an
  app's `before_request` hook) decides what a raised exception means (401, most likely); this
  library never returns an ambiguous "maybe" result.
- **`algorithms` is always passed explicitly to `joserfc.jwt.decode()`, never left to default
  to "whatever the token's header claims."** An unrestricted algorithm list is how "alg
  confusion" signature-bypass attacks happen (e.g. a token claiming `alg: none`, or an RSA
  public key replayed as an HMAC secret). `BearerTokenValidator` defaults to `["RS256"]` — if a
  future consumer's issuer signs with something else, pass `algorithms=` explicitly rather than
  widening the default to "accept anything."
- **JWKS is cached per `BearerTokenValidator` instance** (`jwks_ttl`, default 1h), not fetched
  on every request — avoids a network round trip to COmanage per incoming request. `jwks_uri=`
  bypasses discovery entirely when given (mainly for tests, or an issuer without a discovery
  document).
- **Device-flow polling uses plain `requests`, not joserfc/Authlib.** Unlike token
  *validation*, POSTing form-encoded params to a token endpoint and branching on
  `authorization_pending`/`slow_down`/other-error is plumbing, not cryptography — it doesn't
  benefit from a dedicated library the way signature verification does.
- **A failed refresh falls back to a fresh `login()`, it doesn't raise.** `DeviceLoginError` is
  reserved for the device-code flow itself failing or expiring — a stale/revoked refresh token
  is an expected, recoverable case (`get_access_token()` handles it by re-authenticating), not
  an error the caller needs to handle specially.
- **Token cache location is the caller's choice, not a hardcoded default.**
  `DeviceCodeSession` takes `token_cache_path` explicitly (see `TokenStore`) — different CLIs,
  or the same CLI against different COmanage environments, need different cache files.
- **`groups_claim` defaults to `"groups"`**, matching oauth2-proxy's
  `OAUTH2_PROXY_OIDC_GROUPS_CLAIM` convention used elsewhere in this stack (see
  `web-app-template`'s `for-maintainers.md`) — so a Rego policy in `c3g-opa-policies` doesn't
  have to special-case which tier (3a vs 3b) produced its `input.groups`.

- **The broker forwards an allowlist, never the request as is.** `device_flow_broker` holds a
  confidential client's secret, so its token route accepts only the device-code and refresh-token
  grants, each with its own parameters, and always sends the app's client id and secret. Forwarding
  `client_credentials` would hand the client's own token to anyone; forwarding other parameters
  would let a caller pick the grant's behaviour. Keep the allowlist in `FORWARDED_GRANTS` and test
  every addition.
- **Confidential-client credentials go in the request body** (`client_secret_post`), not HTTP
  Basic: COmanage client ids contain ':', which Basic can't carry without form-encoding.

## Why joserfc, not `authlib.jose`

The original design (see `web-app-template`'s docs) said "built on Authlib." `authlib.jose` —
the submodule that would have provided JWT/JWK handling — is deprecated in favor of `joserfc`,
a sibling project by the same author, meant as its direct successor. `joserfc` is what's
actually used here; `authlib` itself (the OAuth/OIDC client/server integrations package) isn't
a dependency at all, since this library hand-rolls the RFC 8628 client instead (see above).

## Commands

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[server,test]"
.venv/bin/pytest -v
```

Both test files start a real local HTTP server (Flask's dev server, on a background thread, a
free port) rather than mocking `requests` — `test_server.py` signs real RSA JWTs and serves a
real JWKS; `test_client.py` runs a scriptable mock RFC 8628 authorization server. No live
network access or real COmanage instance is needed for either.

CI (`.github/workflows/test.yml`) runs the suite on Python 3.11–3.15.


## Releasing

Publishing a GitHub Release publishes to PyPI (`.github/workflows/publish.yml`, trusted
publishing through the `pypi` environment, no API token stored anywhere):

1. In a PR, bump `c3g_oidc/__version__.py` (e.g. `0.2.0`) and merge it.
2. `gh release create v0.2.0 --generate-notes` (or the repo's Releases page). The tag must be
   `v` + the version in `__version__.py`, or the workflow stops before building.

(Licensed GPL-3.0, matching `project_tracking`
and `project_tracking_cli` — see `LICENSE`.)
