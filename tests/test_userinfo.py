"""Runs UserinfoGroups against a real HTTP mock issuer (Flask's dev server on a background thread)
serving discovery and a userinfo endpoint whose answer each test sets: the groups, the cache, and
how each kind of failure is reported.
"""

from __future__ import annotations

import threading
import time

import pytest
from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from c3g_oidc.server import TokenValidationError, UserinfoGroups, UserinfoUnavailableError


@pytest.fixture
def issuer():
    """state['answer'] is the userinfo (status, body); state['calls'] the Authorization headers it got."""
    app = Flask(__name__)
    state = {"answer": (200, {"sub": "user-1", "groups": ["pt-admins"]}), "calls": [], "userinfo": None}

    @app.route("/.well-known/openid-configuration")
    def discovery():
        return jsonify({"issuer": request.host_url.rstrip("/"),
                        "userinfo_endpoint": state["userinfo"] or request.host_url + "userinfo"})

    @app.route("/userinfo")
    def userinfo():
        state["calls"].append(request.headers.get("Authorization"))
        status, body = state["answer"]
        if isinstance(body, str):
            return body, status
        return jsonify(body), status

    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state["url"] = f"http://127.0.0.1:{server.server_port}"
    yield state
    server.shutdown()
    thread.join(timeout=5)


def _claims(sub="user-1", exp_delta=900):
    return {"sub": sub, "exp": time.time() + exp_delta}


def test_groups_come_from_userinfo_with_the_token(issuer):
    userinfo = UserinfoGroups(issuer["url"])

    assert userinfo.groups("tok-1", _claims()) == ["pt-admins"]
    assert issuer["calls"] == ["Bearer tok-1"]


def test_answer_is_cached_per_token(issuer):
    userinfo = UserinfoGroups(issuer["url"])

    userinfo.groups("tok-1", _claims())
    userinfo.groups("tok-1", _claims())
    userinfo.groups("tok-2", _claims())

    assert issuer["calls"] == ["Bearer tok-1", "Bearer tok-2"]


def test_cache_never_outlives_max_age_or_the_token(issuer):
    short = UserinfoGroups(issuer["url"], max_age=0)
    short.groups("tok-1", _claims())
    short.groups("tok-1", _claims())
    expired = UserinfoGroups(issuer["url"])
    expired.groups("tok-2", _claims(exp_delta=-1))
    expired.groups("tok-2", _claims(exp_delta=-1))

    assert len(issuer["calls"]) == 4


def test_cache_is_bounded(issuer):
    userinfo = UserinfoGroups(issuer["url"], max_entries=2)
    for token in ("tok-1", "tok-2", "tok-3"):
        userinfo.groups(token, _claims())

    assert len(userinfo._cache) == 2
    userinfo.groups("tok-1", _claims())
    assert issuer["calls"][-1] == "Bearer tok-1" and len(issuer["calls"]) == 4


@pytest.mark.parametrize("status", [401, 403])
def test_refused_token_is_invalid(issuer, status):
    issuer["answer"] = (status, {"error": "invalid_token"})

    with pytest.raises(TokenValidationError):
        UserinfoGroups(issuer["url"]).groups("tok-1", _claims())


def test_userinfo_about_another_user_is_invalid(issuer):
    issuer["answer"] = (200, {"sub": "user-2", "groups": ["pt-admins"]})

    with pytest.raises(TokenValidationError, match="another user"):
        UserinfoGroups(issuer["url"]).groups("tok-1", _claims())


@pytest.mark.parametrize("answer", [(500, {"error": "server_error"}), (200, "not json"), (200, ["a list"])])
def test_issuer_that_cant_answer_is_unavailable_and_not_cached(issuer, answer):
    issuer["answer"] = answer
    userinfo = UserinfoGroups(issuer["url"])

    with pytest.raises(UserinfoUnavailableError):
        userinfo.groups("tok-1", _claims())
    issuer["answer"] = (200, {"sub": "user-1", "groups": ["pt-admins"]})
    assert userinfo.groups("tok-1", _claims()) == ["pt-admins"]


def test_unreachable_issuer_is_unavailable():
    with pytest.raises(UserinfoUnavailableError):
        UserinfoGroups("http://127.0.0.1:1", timeout=1).groups("tok-1", _claims())


def test_token_is_only_sent_to_the_issuer(issuer):
    issuer["userinfo"] = "http://127.0.0.1:1/userinfo"

    with pytest.raises(UserinfoUnavailableError, match="isn't on the issuer"):
        UserinfoGroups(issuer["url"]).groups("tok-1", _claims())


def test_missing_or_odd_groups_claim_gives_no_groups(issuer):
    issuer["answer"] = (200, {"sub": "user-1"})
    assert UserinfoGroups(issuer["url"]).groups("tok-1", _claims()) == []
    issuer["answer"] = (200, {"sub": "user-1", "groups": "pt-admins"})
    assert UserinfoGroups(issuer["url"]).groups("tok-2", _claims()) == []
