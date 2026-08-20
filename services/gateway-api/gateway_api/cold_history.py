from __future__ import annotations

import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from .config import Settings


class ColdHistoryUnavailable(RuntimeError):
    pass


class ColdHistoryProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class ColdHistoryPage:
    items: list[dict[str, Any]]
    has_more: bool


class ColdHistoryClient:
    def __init__(
        self,
        *,
        base_url: str,
        ca_cert_path: str,
        client_cert_path: str,
        client_key_path: str,
        connect_timeout_seconds: float,
        read_timeout_seconds: float,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        normalized = base_url.rstrip("/")
        if not normalized.startswith("https://"):
            raise ValueError("cold history base URL must use HTTPS")
        self.base_url = normalized
        if client is None:
            context = ssl.create_default_context(cafile=ca_cert_path)
            context.load_cert_chain(client_cert_path, client_key_path)
            timeout = httpx.Timeout(
                read=read_timeout_seconds,
                write=read_timeout_seconds,
                connect=connect_timeout_seconds,
                pool=connect_timeout_seconds,
            )
            client = httpx.AsyncClient(
                base_url=normalized,
                verify=context,
                timeout=timeout,
                follow_redirects=False,
            )
        self._client = client

    @classmethod
    def from_settings(cls, settings: Settings) -> ColdHistoryClient | None:
        if not settings.gateway_cold_history_enabled:
            return None
        required = {
            "GATEWAY_COLD_HISTORY_BASE_URL": settings.gateway_cold_history_base_url,
            "GATEWAY_COLD_HISTORY_CA_CERT_PATH": settings.gateway_cold_history_ca_cert_path,
            "GATEWAY_COLD_HISTORY_CLIENT_CERT_PATH": settings.gateway_cold_history_client_cert_path,
            "GATEWAY_COLD_HISTORY_CLIENT_KEY_PATH": settings.gateway_cold_history_client_key_path,
        }
        missing = [name for name, value in required.items() if not str(value or "").strip()]
        if missing:
            raise RuntimeError(
                "cold history is enabled but required settings are missing: "
                + ", ".join(sorted(missing))
            )
        return cls(
            base_url=settings.gateway_cold_history_base_url,
            ca_cert_path=settings.gateway_cold_history_ca_cert_path,
            client_cert_path=settings.gateway_cold_history_client_cert_path,
            client_key_path=settings.gateway_cold_history_client_key_path,
            connect_timeout_seconds=settings.gateway_cold_history_connect_timeout_seconds,
            read_timeout_seconds=settings.gateway_cold_history_read_timeout_seconds,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise ColdHistoryUnavailable("cold history store is unavailable") from exc
        if response.status_code >= 500:
            raise ColdHistoryUnavailable(
                f"cold history store returned HTTP {response.status_code}"
            )
        return response

    @staticmethod
    def _json_payload(response: httpx.Response, context: str) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise ColdHistoryProtocolError(
                f"cold history {context} payload is not valid JSON"
            ) from exc

    async def health(self) -> dict[str, Any]:
        response = await self._request("GET", "/v1/health")
        if response.status_code != 200:
            raise ColdHistoryProtocolError(
                f"cold history health returned HTTP {response.status_code}"
            )
        payload = self._json_payload(response, "health")
        if not isinstance(payload, dict) or payload.get("status") != "ok":
            raise ColdHistoryProtocolError("cold history health payload is invalid")
        return payload

    async def get_event(self, event_id: str) -> dict[str, Any] | None:
        response = await self._request("GET", f"/v1/events/{event_id}")
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ColdHistoryProtocolError(
                f"cold history event lookup returned HTTP {response.status_code}"
            )
        payload = self._json_payload(response, "event")
        if not isinstance(payload, dict) or str(payload.get("id") or "") != event_id:
            raise ColdHistoryProtocolError("cold history event payload is invalid")
        return payload

    async def list_event_attempts(self, event_id: str) -> list[dict[str, Any]] | None:
        response = await self._request("GET", f"/v1/events/{event_id}/attempts")
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ColdHistoryProtocolError(
                f"cold history attempt lookup returned HTTP {response.status_code}"
            )
        payload = self._json_payload(response, "attempts")
        if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
            raise ColdHistoryProtocolError("cold history attempts payload is invalid")
        return [dict(item) for item in payload]

    async def list_events(
        self,
        *,
        status: str | None = None,
        owner_subject: str | None = None,
        event_type: str | None = None,
        search: str | None = None,
        before_timestamp: str | None = None,
        before_id: str | None = None,
        include_attempts: bool = False,
        limit: int = 25,
    ) -> ColdHistoryPage:
        params = {
            "status": status,
            "owner_subject": owner_subject,
            "event_type": event_type,
            "search": search,
            "before_timestamp": before_timestamp,
            "before_id": before_id,
            "include_attempts": "true" if include_attempts else "false",
            "limit": str(limit),
        }
        response = await self._request(
            "GET",
            "/v1/events",
            params={key: value for key, value in params.items() if value is not None},
        )
        return self._page(response, "events")

    async def list_attempts(
        self,
        *,
        status: str | None = None,
        outbox_event_id: str | None = None,
        replica_id: str | None = None,
        search: str | None = None,
        before_timestamp: str | None = None,
        before_id: str | None = None,
        limit: int = 25,
    ) -> ColdHistoryPage:
        params = {
            "status": status,
            "outbox_event_id": outbox_event_id,
            "replica_id": replica_id,
            "search": search,
            "before_timestamp": before_timestamp,
            "before_id": before_id,
            "limit": str(limit),
        }
        response = await self._request(
            "GET",
            "/v1/attempts",
            params={key: value for key, value in params.items() if value is not None},
        )
        return self._page(response, "attempts")

    def _page(self, response: httpx.Response, resource: str) -> ColdHistoryPage:
        if response.status_code != 200:
            raise ColdHistoryProtocolError(
                f"cold history {resource} page returned HTTP {response.status_code}"
            )
        payload = self._json_payload(response, f"{resource} page")
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ColdHistoryProtocolError(f"cold history {resource} page is invalid")
        return ColdHistoryPage(
            items=[dict(item) for item in items],
            has_more=bool(payload.get("has_more")),
        )


def item_order_key(item: dict[str, Any], *, timestamp_key: str) -> tuple[datetime, str]:
    value = item.get(timestamp_key)
    if not isinstance(value, str):
        raise ColdHistoryProtocolError(f"history item is missing {timestamp_key}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ColdHistoryProtocolError(
            f"history item has invalid {timestamp_key}"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC), str(item.get("id") or "")


def merge_history_pages(
    hot_items: list[dict[str, Any]],
    cold_items: list[dict[str, Any]],
    *,
    timestamp_key: str,
    limit: int,
    hot_has_more: bool,
    cold_has_more: bool,
) -> tuple[list[dict[str, Any]], bool]:
    merged: dict[str, dict[str, Any]] = {}
    for item in cold_items:
        item_id = str(item.get("id") or "")
        if not item_id:
            raise ColdHistoryProtocolError("cold history item id is missing")
        merged[item_id] = item
    for item in hot_items:
        item_id = str(item.get("id") or "")
        if not item_id:
            raise ColdHistoryProtocolError("hot history item id is missing")
        merged[item_id] = item
    ordered = sorted(
        merged.values(),
        key=lambda item: item_order_key(item, timestamp_key=timestamp_key),
        reverse=True,
    )
    visible = ordered[:limit]
    has_more = len(ordered) > limit or hot_has_more or cold_has_more
    return visible, has_more
