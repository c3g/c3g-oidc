"""Runs device_flow_broker in a Flask app against a real HTTP mock issuer (Flask's dev server on
a background thread) that records every request it receives -- proving the broker adds the
confidential client's credentials, forwards only the device-code and refresh grants with their
own parameters, and passes the issuer's answers through, including to a real DeviceCodeSession.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from c3g_oidc.client import DeviceCodeSession
from c3g_oidc.server import device_flow_broker

CLIENT_ID = "cilogon:/client_id/app"
CLIENT_SECRET = "app-secret"
DEFAULT_SCOPE = "openid email"
DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def _serve(app):
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


@pytest.fixture
def issuer():
    """A mock issuer recording each form it receives in `received`, as (endpoint, form) pairs.
    Device-code polls answer `authorization_pending` once, then a token.
    """
    app = Flask(__name__)
    received = []
    polls = {"n": 0}

    @app.route("/.well-known/openid-configuration")
    def discovery():
        return jsonify({
            "device_authorization_endpoint": request.host_url + "device_authorization",
            "token_endpoint": request.host_url + "token",
        })

    @app.post("/device_authorization")
    def device_authorization():
        received.append(("device_authorization", request.form.to_dict()))
        return jsonify({
            "device_code": "dc1", "user_code": "ABCD-EFGH", "verification_uri": "https://issuer.example/device",
            "expires_in": 30, "interval": 0.02,
        })

    @app.post("/token")
    def token():
        received.append(("token", request.form.to_dict()))
        if request.form.get("grant_type") == DEVICE_CODE_GRANT:
            polls["n"] += 1
            if polls["n"] == 1:
                return jsonify({"error": "authorization_pending"}), 400
        return jsonify({"access_token": "tok", "refresh_token": "ref", "expires_in": 3600})

    server, thread, url = _serve(app)
    yield url, received
    server.shutdown()
    thread.join(timeout=5)


def _app(issuer_url):
    app = Flask(__name__)
    app.register_blueprint(device_flow_broker(issuer_url, CLIENT_ID, CLIENT_SECRET, scope=DEFAULT_SCOPE))
    return app


def test_device_authorization_adds_the_client_and_default_scope(issuer):
    issuer_url, received = issuer
    response = _app(issuer_url).test_client().post("/auth/device_authorization", data={"client_id": "pt-cli"})

    assert response.status_code == 200 and response.get_json()["user_code"] == "ABCD-EFGH"
    assert received == [("device_authorization",
                         {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "scope": DEFAULT_SCOPE})]


def test_device_authorization_keeps_the_requested_scope(issuer):
    issuer_url, received = issuer
    _app(issuer_url).test_client().post("/auth/device_authorization", data={"scope": "openid"})

    assert received[0][1]["scope"] == "openid"


def test_token_passes_the_device_code_poll_and_its_answers_through(issuer):
    issuer_url, received = issuer
    client = _app(issuer_url).test_client()
    form = {"grant_type": DEVICE_CODE_GRANT, "device_code": "dc1", "client_id": "pt-cli"}

    pending = client.post("/auth/token", data=form)
    granted = client.post("/auth/token", data=form)

    assert pending.status_code == 400 and pending.get_json() == {"error": "authorization_pending"}
    assert granted.status_code == 200 and granted.get_json()["access_token"] == "tok"
    assert granted.headers["Cache-Control"] == "no-store"
    assert received[-1] == ("token", {"grant_type": DEVICE_CODE_GRANT, "device_code": "dc1",
                                      "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})


def test_token_forwards_a_refresh(issuer):
    issuer_url, received = issuer
    response = _app(issuer_url).test_client().post(
        "/auth/token", data={"grant_type": "refresh_token", "refresh_token": "ref", "scope": "openid"})

    assert response.status_code == 200
    assert received == [("token", {"grant_type": "refresh_token", "refresh_token": "ref", "scope": "openid",
                                   "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})]


@pytest.mark.parametrize("form", [
    {"grant_type": "client_credentials"},
    {"grant_type": "authorization_code", "code": "c1", "redirect_uri": "https://evil.example"},
    {"grant_type": "password", "username": "u", "password": "p"},
    {},
])
def test_token_refuses_other_grants_without_calling_the_issuer(issuer, form):
    issuer_url, received = issuer
    response = _app(issuer_url).test_client().post("/auth/token", data=form)

    assert response.status_code == 400 and response.get_json()["error"] == "unsupported_grant_type"
    assert received == []


def test_caller_cannot_replace_the_client_or_add_parameters(issuer):
    issuer_url, received = issuer
    _app(issuer_url).test_client().post("/auth/token", data={
        "grant_type": DEVICE_CODE_GRANT, "device_code": "dc1", "client_id": "other", "client_secret": "guess",
        "redirect_uri": "https://evil.example", "code": "c1",
    })

    assert received[0][1] == {"grant_type": DEVICE_CODE_GRANT, "device_code": "dc1",
                              "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}


def test_unreachable_issuer_is_a_502():
    response = _app("http://127.0.0.1:1").test_client().post("/auth/device_authorization")

    assert response.status_code == 502 and response.get_json()["error"] == "temporarily_unavailable"


def test_device_code_session_logs_in_through_the_broker(issuer, tmp_path: Path):
    """A CLI pointed at the app's routes logs in without ever holding the client's secret."""
    issuer_url, received = issuer
    server, thread, app_url = _serve(_app(issuer_url))
    try:
        session = DeviceCodeSession(
            "http://127.0.0.1:1", "pt-cli", str(tmp_path / "token.json"), display=lambda message: None,
            device_authorization_endpoint=f"{app_url}/auth/device_authorization",
            token_endpoint=f"{app_url}/auth/token",
        )
        assert session.get_access_token() == "tok"
    finally:
        server.shutdown()
        thread.join(timeout=5)
    assert [endpoint for endpoint, _ in received] == ["device_authorization", "token", "token"]
    assert all(form["client_secret"] == CLIENT_SECRET for _, form in received)
