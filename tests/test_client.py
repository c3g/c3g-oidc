"""Runs DeviceCodeSession against a real HTTP mock authorization server (Flask's dev server
on a background thread) implementing the RFC 8628 device-authorization and token endpoints,
with canned responses per test -- proving the polling loop, pending/slow_down/error handling,
caching, and refresh logic actually work end to end.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from c3g_oidc.client import DeviceCodeSession, DeviceLoginError, TokenStore


@pytest.fixture
def mock_idp():
    """Factory fixture. Call with `device_auth` (the device_authorization response body),
    `token_sequence` (a list of `(status_code, body)` tuples returned in order, one per
    device-code poll -- the last entry repeats if polled more times than the list's length),
    and optionally `refresh_response` (a single `(status_code, body)` for refresh-grant
    requests). Returns the mock issuer's base URL; tears every server it started down at the
    end of the test.
    """
    servers = []

    def _make(device_auth, token_sequence, refresh_response=None):
        app = Flask(__name__)
        state = {"poll_index": 0}

        @app.route("/.well-known/openid-configuration")
        def discovery():
            return jsonify(
                {
                    "device_authorization_endpoint": request.host_url + "device_authorization",
                    "token_endpoint": request.host_url + "token",
                }
            )

        @app.route("/device_authorization", methods=["POST"])
        def device_authorization():
            return jsonify(device_auth)

        @app.route("/token", methods=["POST"])
        def token():
            if request.form.get("grant_type") == "refresh_token":
                if refresh_response is None:
                    return jsonify({"error": "invalid_grant"}), 400
                status, body = refresh_response
                return jsonify(body), status

            index = state["poll_index"]
            state["poll_index"] += 1
            status, body = token_sequence[min(index, len(token_sequence) - 1)]
            return jsonify(body), status

        server = make_server("127.0.0.1", 0, app)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return f"http://127.0.0.1:{port}"

    yield _make

    for server, thread in servers:
        server.shutdown()
        thread.join(timeout=5)


def _device_auth(**overrides):
    base = {
        "device_code": "dc1",
        "user_code": "ABCD-EFGH",
        "verification_uri": "http://example.org/verify",
        "expires_in": 30,
        "interval": 0.02,
    }
    base.update(overrides)
    return base


def test_login_success_on_first_poll(mock_idp, tmp_path: Path):
    issuer_url = mock_idp(
        device_auth=_device_auth(),
        token_sequence=[(200, {"access_token": "tok1", "refresh_token": "ref1", "expires_in": 3600})],
    )
    messages: list[str] = []
    session = DeviceCodeSession(
        issuer_url, "client1", str(tmp_path / "token.json"), display=messages.append
    )
    assert session.login() == "tok1"
    assert any("ABCD-EFGH" in m for m in messages)

    cached = TokenStore(str(tmp_path / "token.json")).load()
    assert cached["access_token"] == "tok1"
    assert cached["refresh_token"] == "ref1"


def test_login_polls_through_pending(mock_idp, tmp_path: Path):
    issuer_url = mock_idp(
        device_auth=_device_auth(),
        token_sequence=[
            (400, {"error": "authorization_pending"}),
            (400, {"error": "authorization_pending"}),
            (200, {"access_token": "tok2", "expires_in": 3600}),
        ],
    )
    session = DeviceCodeSession(
        issuer_url, "client1", str(tmp_path / "token.json"), display=lambda m: None
    )
    assert session.login() == "tok2"


def test_login_handles_slow_down(mock_idp, tmp_path: Path):
    issuer_url = mock_idp(
        device_auth=_device_auth(),
        token_sequence=[(400, {"error": "slow_down"}), (200, {"access_token": "tok3", "expires_in": 3600})],
    )
    session = DeviceCodeSession(
        issuer_url, "client1", str(tmp_path / "token.json"), display=lambda m: None
    )
    assert session.login() == "tok3"


def test_login_raises_on_access_denied(mock_idp, tmp_path: Path):
    issuer_url = mock_idp(
        device_auth=_device_auth(),
        token_sequence=[(400, {"error": "access_denied", "error_description": "user said no"})],
    )
    session = DeviceCodeSession(
        issuer_url, "client1", str(tmp_path / "token.json"), display=lambda m: None
    )
    with pytest.raises(DeviceLoginError, match="access_denied"):
        session.login()


def test_login_raises_when_flow_expires(mock_idp, tmp_path: Path):
    issuer_url = mock_idp(
        device_auth=_device_auth(expires_in=0.15, interval=0.05),
        token_sequence=[(400, {"error": "authorization_pending"})],
    )
    session = DeviceCodeSession(
        issuer_url, "client1", str(tmp_path / "token.json"), display=lambda m: None
    )
    with pytest.raises(DeviceLoginError, match="expired"):
        session.login()


def test_get_access_token_uses_valid_cache_without_hitting_network(tmp_path: Path):
    store = TokenStore(str(tmp_path / "token.json"))
    store.save(
        {"access_token": "cached-tok", "refresh_token": None, "expires_at": time.time() + 3600, "token_type": "Bearer"}
    )
    # Port 1 is a reserved, unassigned port -- if get_access_token() tried the network at
    # all here, it would fail fast rather than hang, catching a regression either way.
    session = DeviceCodeSession("http://127.0.0.1:1", "client1", str(tmp_path / "token.json"))
    assert session.get_access_token() == "cached-tok"


def test_get_access_token_refreshes_expired_token(mock_idp, tmp_path: Path):
    issuer_url = mock_idp(
        device_auth=_device_auth(),
        token_sequence=[],
        refresh_response=(200, {"access_token": "refreshed-tok", "refresh_token": "new-ref", "expires_in": 3600}),
    )
    store = TokenStore(str(tmp_path / "token.json"))
    store.save(
        {"access_token": "old-tok", "refresh_token": "old-ref", "expires_at": time.time() - 100, "token_type": "Bearer"}
    )
    session = DeviceCodeSession(issuer_url, "client1", str(tmp_path / "token.json"))
    assert session.get_access_token() == "refreshed-tok"
    assert store.load()["access_token"] == "refreshed-tok"


def test_get_access_token_falls_back_to_login_when_refresh_fails(mock_idp, tmp_path: Path):
    issuer_url = mock_idp(
        device_auth=_device_auth(),
        token_sequence=[(200, {"access_token": "fresh-login-tok", "expires_in": 3600})],
        refresh_response=(400, {"error": "invalid_grant"}),
    )
    store = TokenStore(str(tmp_path / "token.json"))
    store.save(
        {"access_token": "old-tok", "refresh_token": "old-ref", "expires_at": time.time() - 100, "token_type": "Bearer"}
    )
    session = DeviceCodeSession(
        issuer_url, "client1", str(tmp_path / "token.json"), display=lambda m: None
    )
    assert session.get_access_token() == "fresh-login-tok"


def test_explicit_endpoints_skip_discovery(mock_idp, tmp_path: Path):
    """With both endpoints given, e.g. an app's forwarding routes, the issuer URL is never contacted."""
    idp_url = mock_idp(
        device_auth=_device_auth(),
        token_sequence=[(200, {"access_token": "tok-explicit", "expires_in": 3600})],
    )
    session = DeviceCodeSession(
        "http://127.0.0.1:1", "client1", str(tmp_path / "token.json"), display=lambda message: None,
        device_authorization_endpoint=f"{idp_url}/device_authorization", token_endpoint=f"{idp_url}/token",
    )
    assert session.login() == "tok-explicit"
