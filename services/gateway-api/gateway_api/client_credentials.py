from __future__ import annotations

import ssl
import threading
import time

import httpx


class ClientCredentialsTokenProvider:
    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str = "",
        timeout_seconds: float = 5.0,
        ca_bundle: str | None = None,
        error_label: str = "application token",
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._timeout_seconds = timeout_seconds
        self._ca_bundle = ca_bundle
        self._error_label = error_label
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = threading.RLock()

    def __repr__(self) -> str:
        return "ClientCredentialsTokenProvider(<redacted>)"

    def get_token(self) -> str:
        with self._lock:
            now = time.monotonic()
            if self._token is not None and now < self._expires_at - 30:
                return self._token
            if not self._token_url or not self._client_id or not self._client_secret:
                raise RuntimeError(
                    f"{self._error_label} credentials are not configured"
                )
            data = {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            }
            if self._scope:
                data["scope"] = self._scope
            context = ssl.create_default_context()
            if self._ca_bundle:
                context.load_verify_locations(cafile=self._ca_bundle)
            try:
                with httpx.Client(
                    timeout=self._timeout_seconds, verify=context
                ) as client:
                    response = client.post(self._token_url, data=data)
                    response.raise_for_status()
                    payload = response.json()
            except (httpx.HTTPError, OSError, ValueError) as error:
                raise RuntimeError(f"{self._error_label} acquisition failed") from error
            token = payload.get("access_token") if isinstance(payload, dict) else None
            expires_in = (
                payload.get("expires_in", 60) if isinstance(payload, dict) else 60
            )
            if not isinstance(token, str) or not token or len(token) > 131072:
                raise RuntimeError(f"{self._error_label} response is invalid")
            if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
                expires_in = 60
            self._token = token
            self._expires_at = now + max(60.0, min(float(expires_in), 86400.0))
            return token
