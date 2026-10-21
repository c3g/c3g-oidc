# c3g-oidc

The in-app OIDC client library C3G apps use for **Tier 3b** authentication — full per-app
identity checks, for when oauth2-proxy's cookie-based gate doesn't serve every client (e.g. a
CLI companion that has no browser to sit behind a proxy). See
[web-app-template](https://github.com/c3g/web-app-template)'s `for-app-developers.md` and
`README.md` for where this fits among the authentication/authorization tiers.

Two independent halves, installable and importable separately:

- **`c3g_oidc.server`** — validates a Bearer token inside a Flask app (signature, expiry,
  issuer, audience — via [joserfc](https://jose.authlib.org/), Authlib's JOSE library) and
  exposes its groups claim, so `c3g-flask-opa` can use it as a groups source for
  authorization decisions.
- **`c3g_oidc.client`** — no Flask dependency. What a CLI companion (like `pt_cli`) uses to log
  in via the OIDC device-code flow (RFC 8628), cache the resulting token, and refresh it
  automatically without a browser.

**Status: working, and verified for real** — not a mocked-out stub. `server`'s test suite
signs real RSA-backed JWTs and validates them against a real HTTP-served JWKS, proving
signature/issuer/audience/expiry checks and JWKS caching all work; `client`'s test suite runs
the device-code flow (including `authorization_pending`, `slow_down`, `access_denied`,
expiry, caching, and refresh) against a real mock authorization server. See
[CLAUDE.md](CLAUDE.md) for how to run either yourself.

## Install

```bash
pip install c3g-oidc            # client half only
pip install "c3g-oidc[server]"  # + Flask/joserfc server half
```

## Usage

### Server half (inside a Flask app)

```python
from flask import g, request
from c3g_oidc.server import BearerTokenValidator

validator = BearerTokenValidator(
    issuer_url="https://comanage.example/oidc",
    audience="my-app",
)

@app.before_request
def load_groups():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    g.groups = validator.validate(token)  # raises TokenValidationError on anything invalid
```

`g.groups` is then what you pass as the groups-source callable to `c3g-flask-opa`.

### Client half (inside a CLI)

```python
from c3g_oidc.client import DeviceCodeSession

session = DeviceCodeSession(
    issuer_url="https://comanage.example/oidc",
    client_id="pt-cli",
    token_cache_path="~/.cache/pt_cli/token.json",
)

token = session.get_access_token()  # interactive device-code login on first use,
                                     # silent cache/refresh on every call after that
```
