"""Runs BearerTokenValidator against a real, locally-generated RSA key/JWKS and a real HTTP
server (Flask's dev server on a background thread) serving discovery + JWKS endpoints --
proving signature verification, issuer/audience/expiry checks, and JWKS caching actually
work, not just that the code parses.
"""

from __future__ import annotations

import threading
import time

import pytest
from flask import Flask, jsonify, request
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import KeySet, RSAKey
from werkzeug.serving import make_server

from c3g_oidc.server import BearerTokenValidator, TokenValidationError

AUDIENCE = "test-app"


def make_token(key, *, iss, aud=AUDIENCE, groups=None, exp_delta=300, alg="RS256", **extra):
    now = int(time.time())
    claims = {"iss": iss, "aud": aud, "iat": now, "exp": now + exp_delta, **extra}
    if groups is not None:
        claims["groups"] = groups
    header = {"alg": alg, "kid": key.kid}
    return joserfc_jwt.encode(header, claims, key)


@pytest.fixture(scope="module")
def signing_key():
    return RSAKey.generate_key(2048, private=True, auto_kid=True)


@pytest.fixture(scope="module")
def other_key():
    """A second key, never published in the served JWKS -- used to prove a token signed by
    an untrusted key is rejected, not just accepted because claims happen to look right.
    """
    return RSAKey.generate_key(2048, private=True, auto_kid=True)


@pytest.fixture(scope="module")
def issuer(signing_key):
    app = Flask(__name__)
    public_jwks = KeySet([signing_key]).as_dict(private=False)
    jwks_fetch_count = {"n": 0}

    @app.route("/.well-known/openid-configuration")
    def discovery():
        return jsonify({"jwks_uri": request.host_url + "jwks", "issuer": request.host_url})

    @app.route("/jwks")
    def jwks():
        jwks_fetch_count["n"] += 1
        return jsonify(public_jwks)

    server = make_server("127.0.0.1", 0, app)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", jwks_fetch_count
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_valid_token_returns_groups(issuer, signing_key):
    issuer_url, _ = issuer
    validator = BearerTokenValidator(issuer_url, AUDIENCE)
    token = make_token(signing_key, iss=issuer_url, groups=["example-admins", "example-viewers"])
    assert validator.validate(token) == ["example-admins", "example-viewers"]


def test_missing_groups_claim_returns_empty_list(issuer, signing_key):
    issuer_url, _ = issuer
    validator = BearerTokenValidator(issuer_url, AUDIENCE)
    token = make_token(signing_key, iss=issuer_url)
    assert validator.validate(token) == []


def test_wrong_audience_rejected(issuer, signing_key):
    issuer_url, _ = issuer
    validator = BearerTokenValidator(issuer_url, AUDIENCE)
    token = make_token(signing_key, iss=issuer_url, aud="some-other-app")
    with pytest.raises(TokenValidationError):
        validator.validate(token)


def test_wrong_issuer_rejected(issuer, signing_key):
    issuer_url, _ = issuer
    validator = BearerTokenValidator(issuer_url, AUDIENCE)
    token = make_token(signing_key, iss="https://not-the-real-issuer.example")
    with pytest.raises(TokenValidationError):
        validator.validate(token)


def test_expired_token_rejected(issuer, signing_key):
    issuer_url, _ = issuer
    validator = BearerTokenValidator(issuer_url, AUDIENCE, leeway=0)
    token = make_token(signing_key, iss=issuer_url, exp_delta=-60)
    with pytest.raises(TokenValidationError):
        validator.validate(token)


def test_token_within_leeway_is_accepted(issuer, signing_key):
    """A token that expired 10s ago is still accepted with the default 30s leeway -- proves
    leeway is actually wired through to the claims registry, not just accepted as a
    constructor arg and ignored.
    """
    issuer_url, _ = issuer
    validator = BearerTokenValidator(issuer_url, AUDIENCE, leeway=30)
    token = make_token(signing_key, iss=issuer_url, exp_delta=-10)
    assert validator.validate(token) == []


def test_token_signed_by_untrusted_key_rejected(issuer, other_key):
    """The key here is never published in the served JWKS -- proves signature verification
    is actually enforced, not just claims-checking on an unverified payload.
    """
    issuer_url, _ = issuer
    validator = BearerTokenValidator(issuer_url, AUDIENCE)
    token = make_token(other_key, iss=issuer_url)
    with pytest.raises(TokenValidationError):
        validator.validate(token)


def test_garbage_token_rejected(issuer):
    issuer_url, _ = issuer
    validator = BearerTokenValidator(issuer_url, AUDIENCE)
    with pytest.raises(TokenValidationError):
        validator.validate("not-a-real-jwt")


def test_empty_token_rejected(issuer):
    issuer_url, _ = issuer
    validator = BearerTokenValidator(issuer_url, AUDIENCE)
    with pytest.raises(TokenValidationError):
        validator.validate("")


def test_custom_groups_claim(issuer, signing_key):
    issuer_url, _ = issuer
    validator = BearerTokenValidator(issuer_url, AUDIENCE, groups_claim="my_groups")
    token = make_token(signing_key, iss=issuer_url, my_groups=["admins"])
    assert validator.validate(token) == ["admins"]


def test_jwks_is_cached_across_calls(issuer, signing_key):
    issuer_url, fetch_count = issuer
    validator = BearerTokenValidator(issuer_url, AUDIENCE, jwks_ttl=3600)
    before = fetch_count["n"]
    token = make_token(signing_key, iss=issuer_url)
    validator.validate(token)
    validator.validate(token)
    validator.validate(token)
    assert fetch_count["n"] == before + 1


def test_jwks_uri_override_skips_discovery(signing_key):
    """With jwks_uri given explicitly, no discovery call is needed at all -- validate()
    should work even against an issuer_url that doesn't serve a discovery document.
    """
    import threading as _threading

    app = Flask(__name__)
    public_jwks = KeySet([signing_key]).as_dict(private=False)

    @app.route("/only-jwks")
    def jwks():
        return jsonify(public_jwks)

    server = make_server("127.0.0.1", 0, app)
    port = server.server_port
    thread = _threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        validator = BearerTokenValidator(
            "https://issuer.invalid",  # deliberately not reachable/no discovery doc
            AUDIENCE,
            jwks_uri=f"http://127.0.0.1:{port}/only-jwks",
        )
        token = make_token(signing_key, iss="https://issuer.invalid")
        assert validator.validate(token) == []
    finally:
        server.shutdown()
        thread.join(timeout=5)
