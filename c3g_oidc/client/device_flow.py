"""OIDC device-code login for non-browser clients (e.g. a CLI).

Design (see web-app-template's for-app-developers.md): what a CLI companion like `pt_cli`
uses instead of oauth2-proxy's cookie-based browser flow -- there's no browser to send a
device-code CLI through, so it authenticates by displaying a short code and verification URL
for the user to open on any device, then polls the token endpoint until they approve it
(RFC 8628, the OAuth 2.0 Device Authorization Grant).

Plain `requests`, not joserfc/Authlib -- unlike token *validation* (see `server/validator.py`),
polling a token endpoint with form-encoded parameters and handling a handful of well-specified
error codes isn't the kind of thing that benefits from a dedicated crypto library.
"""

from __future__ import annotations

import time

import requests

from .token_store import TokenStore
from ..discovery import discover

# RFC 8628 §3.5 error codes that mean "keep polling" rather than "stop".
_AUTHORIZATION_PENDING = "authorization_pending"
_SLOW_DOWN = "slow_down"


class DeviceLoginError(Exception):
    """Raised when the device-code login flow fails or expires before the user approves
    it, or when a token refresh fails outright (as opposed to simply being absent, which
    just means falling back to a fresh login).
    """


class DeviceCodeSession:
    """Manages a device-code OIDC login for one app/client against one issuer.

    Parameters
    ----------
    issuer_url:
        The OIDC issuer to authenticate against (COmanage). Used to discover the
        `device_authorization_endpoint` and `token_endpoint` via
        `.well-known/openid-configuration`.
    client_id:
        This client's registered OIDC client ID.
    token_cache_path:
        Where to persist the token between runs -- caller's choice (see `TokenStore`), so
        different CLIs, or the same CLI against different environments, don't collide.
    scope:
        Space-separated OIDC scopes to request. Optional -- omitted from the request
        entirely if not given, letting the issuer apply its own default.
    display:
        Callable given the message to show the user (verification URL + code). Defaults to
        `print`; pass something else to route it through a CLI's own output/logging.
    device_authorization_endpoint, token_endpoint:
        Explicit endpoints, overriding the ones discovery finds. With both given, there is no
        discovery at all: e.g. an app's own forwarding routes (`c3g_oidc.server.device_flow_broker`)
        that add a confidential client's secret, which then never reaches the CLI.
    """

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        token_cache_path: str,
        *,
        scope: str | None = None,
        timeout: float = 10.0,
        display=print,
        device_authorization_endpoint: str | None = None,
        token_endpoint: str | None = None,
    ) -> None:
        self.issuer_url = issuer_url.rstrip("/")
        self.client_id = client_id
        self.scope = scope
        self.timeout = timeout
        self._display = display
        self._store = TokenStore(token_cache_path)
        self._metadata: dict | None = None
        self._endpoints = {
            name: url
            for name, url in (
                ("device_authorization_endpoint", device_authorization_endpoint),
                ("token_endpoint", token_endpoint),
            )
            if url
        }

    def _get_metadata(self) -> dict:
        if self._metadata is None:
            if len(self._endpoints) == 2:
                self._metadata = dict(self._endpoints)
            else:
                self._metadata = {**discover(self.issuer_url, timeout=self.timeout), **self._endpoints}
        return self._metadata

    def get_access_token(self) -> str:
        """Return a valid access token: from cache, refreshed, or via a fresh interactive
        device-code login, in that order of preference.
        """
        token = self._store.load()

        if token is not None and not self._is_expired(token):
            return token["access_token"]

        if token is not None and token.get("refresh_token"):
            refreshed = self._try_refresh(token["refresh_token"])
            if refreshed is not None:
                return refreshed["access_token"]

        return self.login()

    def login(self) -> str:
        """Run the interactive device-code login flow: print a verification URL and code,
        poll the token endpoint until the user approves it, cache the result via
        `TokenStore`, and return the access token.
        """
        token = self._run_device_code_flow()
        self._store.save(token)
        return token["access_token"]

    def _is_expired(self, token: dict, leeway: int = 30) -> bool:
        return time.time() >= token.get("expires_at", 0) - leeway

    def _run_device_code_flow(self) -> dict:
        metadata = self._get_metadata()

        request_data = {"client_id": self.client_id}
        if self.scope:
            request_data["scope"] = self.scope

        response = requests.post(
            metadata["device_authorization_endpoint"], data=request_data, timeout=self.timeout
        )
        response.raise_for_status()
        device_auth = response.json()

        verification_uri = device_auth.get("verification_uri_complete") or device_auth["verification_uri"]
        self._display(
            f"To log in, open {verification_uri} "
            f"and enter code: {device_auth['user_code']}"
        )

        return self._poll_for_token(
            metadata["token_endpoint"],
            device_code=device_auth["device_code"],
            interval=device_auth.get("interval", 5),
            expires_in=device_auth["expires_in"],
        )

    def _poll_for_token(self, token_endpoint: str, *, device_code: str, interval: int, expires_in: int) -> dict:
        deadline = time.monotonic() + expires_in

        while time.monotonic() < deadline:
            time.sleep(interval)

            response = requests.post(
                token_endpoint,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": self.client_id,
                },
                timeout=self.timeout,
            )
            body = response.json()

            if response.status_code == 200:
                return self._normalize_token(body)

            error = body.get("error")
            if error == _AUTHORIZATION_PENDING:
                continue
            if error == _SLOW_DOWN:
                interval += 5
                continue

            raise DeviceLoginError(
                f"device login failed: {error or response.status_code} "
                f"({body.get('error_description', 'no description')})"
            )

        raise DeviceLoginError("device login expired before the user approved it")

    def _try_refresh(self, refresh_token: str) -> dict | None:
        """Attempt a refresh; return the new token dict on success, or None on any
        failure -- a failed refresh isn't itself an error, since the caller falls back to
        `login()` when this returns None.
        """
        try:
            metadata = self._get_metadata()
            response = requests.post(
                metadata["token_endpoint"],
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": self.client_id,
                },
                timeout=self.timeout,
            )
            if response.status_code != 200:
                return None
            token = self._normalize_token(response.json())
        except requests.RequestException:
            return None

        self._store.save(token)
        return token

    def _normalize_token(self, body: dict) -> dict:
        return {
            "access_token": body["access_token"],
            "refresh_token": body.get("refresh_token"),
            "expires_at": time.time() + body.get("expires_in", 3600),
            "token_type": body.get("token_type", "Bearer"),
        }
