"""Device-code login forwarded through the app, for a CLI whose OIDC client is confidential.

Some issuers (COmanage/CILogon) release groups only to confidential clients, and a CLI can't keep
a secret: every installed copy would hold it. So the app keeps the secret, and exposes the two
RFC 8628 endpoints a `DeviceCodeSession` needs (point its `device_authorization_endpoint` and
`token_endpoint` at them). Each route adds the client id and secret, forwards the request to the
issuer, and returns the issuer's answer unchanged. The user still logs in at the issuer, through
the verification URL it returns.

Only the device-code and refresh-token grants go through, with only their own parameters: the
token route never forwards client_credentials (anyone could then get the client's own token
without logging in), authorization codes, or a caller's client id or secret.
"""

from __future__ import annotations

import requests
from flask import Blueprint, jsonify, request

from ..discovery import discover

DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
REFRESH_TOKEN_GRANT = "refresh_token"
# grant_type -> the request parameters forwarded with it (beside grant_type, and the client's id and secret)
FORWARDED_GRANTS = {
    DEVICE_CODE_GRANT: ("device_code",),
    REFRESH_TOKEN_GRANT: ("refresh_token", "scope"),
}
# Token responses must not be cached (RFC 6749 §5.1)
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def device_flow_broker(
    issuer_url: str,
    client_id: str,
    client_secret: str,
    *,
    scope: str | None = None,
    name: str = "oidc_broker",
    url_prefix: str = "/auth",
    timeout: float = 10.0,
) -> Blueprint:
    """A blueprint with ``POST <url_prefix>/device_authorization`` and ``POST <url_prefix>/token``,
    forwarding device-code logins and refreshes to `issuer_url` as the confidential client
    `client_id`. Register it on the app, and exempt both routes from its own authentication and
    authorization: the caller isn't logged in yet.

    Parameters
    ----------
    scope:
        Scopes requested when the CLI doesn't ask for any, e.g. ``"openid profile email
        org.cilogon.userinfo"``.
    """
    blueprint = Blueprint(name, __name__, url_prefix=url_prefix)
    endpoints: dict = {}

    def issuer_endpoint(key: str) -> str:
        if not endpoints:
            endpoints.update(discover(issuer_url, timeout=timeout))
        return endpoints[key]

    def forward(key: str, data: dict):
        data.update({"client_id": client_id, "client_secret": client_secret})
        try:
            response = requests.post(issuer_endpoint(key), data=data, timeout=timeout)
        except (requests.RequestException, KeyError) as exc:
            body = {"error": "temporarily_unavailable", "error_description": f"identity provider unreachable: {exc}"}
            return jsonify(body), 502, NO_STORE
        headers = {"Content-Type": response.headers.get("Content-Type", "application/json"), **NO_STORE}
        return response.content, response.status_code, headers

    @blueprint.post("/device_authorization")
    def device_authorization():
        """Start a device-code login at the identity provider (RFC 8628 §3.1), as the app's client."""
        requested = request.form.get("scope") or scope
        return forward("device_authorization_endpoint", {"scope": requested} if requested else {})

    @blueprint.post("/token")
    def token():
        """Poll a device-code login or refresh a token (RFC 8628 §3.4, RFC 6749 §6), as the app's client."""
        grant_type = request.form.get("grant_type")
        if grant_type not in FORWARDED_GRANTS:
            body = {
                "error": "unsupported_grant_type",
                "error_description": "only the device_code and refresh_token grants are accepted here",
            }
            return jsonify(body), 400, NO_STORE
        data = {"grant_type": grant_type}
        data.update({key: request.form[key] for key in FORWARDED_GRANTS[grant_type] if request.form.get(key)})
        return forward("token_endpoint", data)

    return blueprint
