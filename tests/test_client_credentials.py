"""Runs ClientCredentialsSession against a real HTTP mock token endpoint (Flask's dev server on a
background thread) -- proving a robot sends its credentials in the body, caches its token until
it expires, and fails with ClientCredentialsError when refused.
"""

from __future__ import annotations

import threading

import pytest
from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from c3g_oidc.client import ClientCredentialsError, ClientCredentialsSession

CLIENT_ID = "cilogon:oa4mp,2012:/client_id/robot"
SECRET = "robot-secret"


@pytest.fixture
def token_endpoint():
    """A mock issuer issuing tokens numbered from 1 to the right client; `expires_in` sets their lifetime."""
    app = Flask(__name__)
    state = {"issued": 0, "expires_in": 3600, "forms": []}

    @app.route("/.well-known/openid-configuration")
    def discovery():
        return jsonify({"token_endpoint": request.host_url + "token"})

    @app.post("/token")
    def token():
        state["forms"].append(request.form.to_dict())
        if (request.form.get("client_id"), request.form.get("client_secret")) != (CLIENT_ID, SECRET):
            return jsonify({"error": "invalid_client", "error_description": "bad credentials"}), 401
        state["issued"] += 1
        return jsonify({"access_token": f"tok{state['issued']}", "expires_in": state["expires_in"]})

    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", state
    server.shutdown()
    thread.join(timeout=5)


def test_gets_and_caches_a_token(token_endpoint):
    issuer_url, state = token_endpoint
    session = ClientCredentialsSession(issuer_url, CLIENT_ID, SECRET, scope="openid")

    assert session.get_access_token() == "tok1"
    assert session.get_access_token() == "tok1"
    assert state["forms"] == [{"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": SECRET,
                               "scope": "openid"}]


def test_asks_again_once_the_token_expires(token_endpoint):
    issuer_url, state = token_endpoint
    state["expires_in"] = 10  # within the 30 s margin: expired at once
    session = ClientCredentialsSession(issuer_url, CLIENT_ID, SECRET)

    assert session.get_access_token() == "tok1"
    assert session.get_access_token() == "tok2"


def test_explicit_token_endpoint_skips_discovery(token_endpoint):
    issuer_url, _ = token_endpoint
    session = ClientCredentialsSession("http://127.0.0.1:1", CLIENT_ID, SECRET, token_endpoint=f"{issuer_url}/token")

    assert session.get_access_token() == "tok1"


def test_refused_credentials_raise(token_endpoint):
    issuer_url, _ = token_endpoint
    with pytest.raises(ClientCredentialsError, match="invalid_client"):
        ClientCredentialsSession(issuer_url, CLIENT_ID, "wrong").get_access_token()


def test_unreachable_issuer_raises():
    with pytest.raises(ClientCredentialsError, match="could not get a token"):
        ClientCredentialsSession("http://127.0.0.1:1", CLIENT_ID, SECRET, timeout=2).get_access_token()
