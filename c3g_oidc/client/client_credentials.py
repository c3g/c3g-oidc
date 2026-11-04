"""OIDC client-credentials login for robots (OAuth 2.0 client credentials grant, RFC 6749 §4.4).

What an automated job uses instead of `DeviceCodeSession`: nobody is there to open a
verification URL, so the job logs in as its own confidential client, with a secret only it
holds, and gets a token that represents the client, not a person. There is no refresh token:
when the access token expires, the session simply asks for a new one with the secret.

The secret is sent in the request body (`client_secret_post`), not with HTTP Basic: COmanage
client ids contain ':', which Basic authentication can't carry without the form-encoding few
servers implement.
"""

from __future__ import annotations

import time

import requests

from ..discovery import discover


class ClientCredentialsError(Exception):
    """Raised when the token endpoint refuses the client's credentials or can't be reached."""


class ClientCredentialsSession:
    """Gets and caches, in memory, an access token for one confidential client.

    Parameters
    ----------
    issuer_url:
        The OIDC issuer, used to discover the `token_endpoint` unless it is given explicitly.
    client_id, client_secret:
        The robot's own confidential client. Read the secret from wherever the robot keeps it
        (a file only its account can read, a CI secret store); it is only ever sent to the
        token endpoint.
    scope:
        Space-separated scopes to request. Optional: omitted, the issuer applies its default.
    token_endpoint:
        Explicit token endpoint, skipping discovery.
    """

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        client_secret: str,
        *,
        scope: str | None = None,
        token_endpoint: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.issuer_url = issuer_url.rstrip("/")
        self.client_id = client_id
        self.scope = scope
        self.timeout = timeout
        self._client_secret = client_secret
        self._token_endpoint = token_endpoint
        self._token: dict | None = None

    def get_access_token(self) -> str:
        """Return a valid access token: the cached one, or a new one from the token endpoint."""
        if self._token is None or time.time() >= self._token["expires_at"] - 30:
            self._token = self._request_token()
        return self._token["access_token"]

    def _request_token(self) -> dict:
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self._client_secret,
        }
        if self.scope:
            data["scope"] = self.scope
        try:
            token_endpoint = self._token_endpoint or discover(self.issuer_url, timeout=self.timeout)["token_endpoint"]
            response = requests.post(token_endpoint, data=data, timeout=self.timeout)
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise ClientCredentialsError(f"could not get a token: {exc}") from exc
        if response.status_code != 200 or "access_token" not in body:
            raise ClientCredentialsError(
                f"token request refused: {body.get('error') or response.status_code} "
                f"({body.get('error_description', 'no description')})"
            )
        return {"access_token": body["access_token"], "expires_at": time.time() + body.get("expires_in", 3600)}
