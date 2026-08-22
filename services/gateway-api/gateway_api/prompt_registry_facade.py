from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Settings

_CHANNEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_BUNDLE_RE = re.compile(r"^[0-9a-f]{64}$")
_BROWSER_CACHE_CONTROL = "private, max-age=0, must-revalidate"
_NO_STORE = "no-store"


@dataclass(frozen=True, slots=True)
class PromptFacadeResult:
    status_code: int
    payload: dict[str, Any] | None
    headers: dict[str, str]


class PromptRegistryFacadeError(RuntimeError):
    def __init__(
        self,
        status_code: int,
        detail: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.headers = headers or {}


@dataclass(slots=True)
class _CacheEntry:
    payload: dict[str, Any]
    etag: str
    validated_at: float
    max_stale_seconds: float


class PromptRegistryFacade:
    """Authenticated Gateway read-through boundary for immutable prompt releases."""

    def __init__(
        self,
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self._clock = clock
        self._manifest_cache: dict[str, _CacheEntry] = {}
        self._bundle_cache: dict[str, _CacheEntry] = {}
        self._bundle_stale_limits: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self._owns_client = client is None
        token = settings.gateway_prompt_registry_service_token.get_secret_value()
        self._configured = bool(
            settings.gateway_prompt_registry_enabled
            and settings.gateway_prompt_registry_base_url.strip()
            and token
        )
        if client is not None:
            self._client: httpx.AsyncClient | None = client
        elif settings.gateway_prompt_registry_enabled:
            timeout = httpx.Timeout(
                connect=settings.gateway_prompt_registry_connect_timeout_seconds,
                read=settings.gateway_prompt_registry_read_timeout_seconds,
                write=settings.gateway_prompt_registry_read_timeout_seconds,
                pool=settings.gateway_prompt_registry_connect_timeout_seconds,
            )
            self._client = httpx.AsyncClient(
                base_url=settings.gateway_prompt_registry_base_url.rstrip("/"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=timeout,
            )
        else:
            self._client = None

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    def _ensure_configured(self) -> httpx.AsyncClient:
        if not self._configured or self._client is None:
            raise PromptRegistryFacadeError(
                503,
                "Prompt registry facade is not configured",
                headers={"Cache-Control": _NO_STORE},
            )
        return self._client

    def _is_fresh(self, entry: _CacheEntry) -> bool:
        age = max(0.0, self._clock() - entry.validated_at)
        return age < self.settings.gateway_prompt_registry_revalidate_after_seconds

    def _can_serve_stale(self, entry: _CacheEntry) -> bool:
        allowed = min(
            entry.max_stale_seconds,
            float(self.settings.gateway_prompt_registry_max_stale_seconds),
        )
        if allowed <= 0:
            return False
        return max(0.0, self._clock() - entry.validated_at) <= allowed

    @staticmethod
    def _result(
        entry: _CacheEntry,
        browser_etag: str | None,
        *,
        cache_status: str,
        stale: bool = False,
    ) -> PromptFacadeResult:
        headers = {
            "ETag": entry.etag,
            "Cache-Control": _BROWSER_CACHE_CONTROL,
            "X-Prompt-Cache": cache_status,
        }
        if stale:
            headers["Warning"] = '110 - "Response is stale"'
        if browser_etag == entry.etag:
            return PromptFacadeResult(status_code=304, payload=None, headers=headers)
        return PromptFacadeResult(
            status_code=200, payload=entry.payload, headers=headers
        )

    @staticmethod
    def _upstream_error(response: httpx.Response) -> PromptRegistryFacadeError:
        headers = {"Cache-Control": _NO_STORE}
        if response.status_code == 404:
            return PromptRegistryFacadeError(
                404, "Prompt registry object not found", headers=headers
            )
        if response.status_code == 410:
            return PromptRegistryFacadeError(
                410, "Prompt registry release revoked", headers=headers
            )
        if response.status_code in {401, 403}:
            return PromptRegistryFacadeError(
                502, "Prompt registry authentication failed", headers=headers
            )
        return PromptRegistryFacadeError(
            503,
            "Prompt registry is temporarily unavailable",
            headers={**headers, "Retry-After": "1"},
        )

    @staticmethod
    def _json_object(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise PromptRegistryFacadeError(
                502,
                "Prompt registry returned invalid JSON",
                headers={"Cache-Control": _NO_STORE},
            ) from exc
        if not isinstance(payload, dict):
            raise PromptRegistryFacadeError(
                502,
                "Prompt registry returned an invalid payload",
                headers={"Cache-Control": _NO_STORE},
            )
        return payload

    @staticmethod
    def _response_etag(response: httpx.Response) -> str:
        etag = response.headers.get("etag", "").strip()
        if not etag:
            raise PromptRegistryFacadeError(
                502,
                "Prompt registry response is missing ETag",
                headers={"Cache-Control": _NO_STORE},
            )
        return etag

    def _validate_manifest(
        self,
        channel: str,
        response: httpx.Response,
    ) -> _CacheEntry:
        payload = self._json_object(response)
        required_strings = (
            "channel",
            "release_id",
            "bundle_id",
            "sha256",
            "etag",
            "cache_scope_id",
        )
        if any(
            not isinstance(payload.get(key), str) or not payload[key]
            for key in required_strings
        ):
            raise PromptRegistryFacadeError(
                502,
                "Prompt registry manifest is invalid",
                headers={"Cache-Control": _NO_STORE},
            )
        if payload["channel"] != channel or payload["bundle_id"] != payload["sha256"]:
            raise PromptRegistryFacadeError(
                502,
                "Prompt registry manifest integrity check failed",
                headers={"Cache-Control": _NO_STORE},
            )
        if not _BUNDLE_RE.fullmatch(payload["bundle_id"]):
            raise PromptRegistryFacadeError(
                502,
                "Prompt registry manifest bundle identity is invalid",
                headers={"Cache-Control": _NO_STORE},
            )
        etag = self._response_etag(response)
        if payload["etag"] != etag:
            raise PromptRegistryFacadeError(
                502,
                "Prompt registry manifest ETag mismatch",
                headers={"Cache-Control": _NO_STORE},
            )
        generation = payload.get("generation")
        release_generation = payload.get("release_generation")
        max_stale = payload.get("max_stale_seconds")
        if (
            not isinstance(generation, int)
            or generation < 0
            or not isinstance(release_generation, int)
            or release_generation < 0
            or not isinstance(max_stale, int | float)
            or isinstance(max_stale, bool)
            or max_stale < 0
        ):
            raise PromptRegistryFacadeError(
                502,
                "Prompt registry manifest cache metadata is invalid",
                headers={"Cache-Control": _NO_STORE},
            )
        bounded = min(
            float(max_stale),
            float(self.settings.gateway_prompt_registry_max_stale_seconds),
        )
        bundle_id = payload["bundle_id"]
        self._bundle_stale_limits[bundle_id] = bounded
        cached_bundle = self._bundle_cache.get(bundle_id)
        if cached_bundle is not None:
            cached_bundle.max_stale_seconds = bounded
        return _CacheEntry(
            payload=payload,
            etag=etag,
            validated_at=self._clock(),
            max_stale_seconds=bounded,
        )

    def _validate_bundle(self, bundle_id: str, response: httpx.Response) -> _CacheEntry:
        payload = self._json_object(response)
        if payload.get("sha256") != bundle_id:
            raise PromptRegistryFacadeError(
                502,
                "Prompt registry bundle integrity check failed",
                headers={"Cache-Control": _NO_STORE},
            )
        etag = self._response_etag(response)
        if etag != f'"sha256:{bundle_id}"':
            raise PromptRegistryFacadeError(
                502,
                "Prompt registry bundle ETag mismatch",
                headers={"Cache-Control": _NO_STORE},
            )
        max_stale = self._bundle_stale_limits.get(bundle_id, 0.0)
        return _CacheEntry(
            payload=payload,
            etag=etag,
            validated_at=self._clock(),
            max_stale_seconds=max_stale,
        )

    def _purge_channel(self, channel: str, *, purge_bundle: bool) -> None:
        entry = self._manifest_cache.pop(channel, None)
        if purge_bundle and entry is not None:
            bundle_id = entry.payload.get("bundle_id")
            if isinstance(bundle_id, str):
                self._bundle_cache.pop(bundle_id, None)
                self._bundle_stale_limits.pop(bundle_id, None)

    def _purge_bundle(self, bundle_id: str) -> None:
        self._bundle_cache.pop(bundle_id, None)
        self._bundle_stale_limits.pop(bundle_id, None)
        channels = [
            channel
            for channel, entry in self._manifest_cache.items()
            if entry.payload.get("bundle_id") == bundle_id
        ]
        for channel in channels:
            self._manifest_cache.pop(channel, None)

    async def get_manifest(
        self,
        channel: str,
        *,
        browser_etag: str | None = None,
    ) -> PromptFacadeResult:
        if not _CHANNEL_RE.fullmatch(channel):
            raise PromptRegistryFacadeError(
                400, "Invalid prompt channel", headers={"Cache-Control": _NO_STORE}
            )
        client = self._ensure_configured()
        async with self._lock:
            cached = self._manifest_cache.get(channel)
            if cached is not None and self._is_fresh(cached):
                return self._result(cached, browser_etag, cache_status="fresh")
            headers: dict[str, str] = {}
            if cached is not None:
                headers["If-None-Match"] = cached.etag
            try:
                response = await client.get(
                    f"/v1/releases/{channel}/manifest", headers=headers
                )
            except httpx.RequestError as exc:
                if cached is not None and self._can_serve_stale(cached):
                    return self._result(
                        cached, browser_etag, cache_status="stale", stale=True
                    )
                raise PromptRegistryFacadeError(
                    503,
                    "Prompt registry is temporarily unavailable",
                    headers={"Cache-Control": _NO_STORE, "Retry-After": "1"},
                ) from exc
            if response.status_code == 304:
                if cached is None:
                    raise PromptRegistryFacadeError(
                        502,
                        "Prompt registry returned an unexpected 304",
                        headers={"Cache-Control": _NO_STORE},
                    )
                cached.validated_at = self._clock()
                return self._result(cached, browser_etag, cache_status="revalidated")
            if response.status_code == 200:
                entry = self._validate_manifest(channel, response)
                old = self._manifest_cache.get(channel)
                self._manifest_cache[channel] = entry
                if old is not None and old.payload.get(
                    "bundle_id"
                ) != entry.payload.get("bundle_id"):
                    old_bundle = old.payload.get("bundle_id")
                    if isinstance(old_bundle, str):
                        self._bundle_cache.pop(old_bundle, None)
                        self._bundle_stale_limits.pop(old_bundle, None)
                return self._result(entry, browser_etag, cache_status="miss")
            if response.status_code in {404, 410}:
                self._purge_channel(channel, purge_bundle=response.status_code == 410)
                raise self._upstream_error(response)
            if (
                response.status_code >= 500
                and cached is not None
                and self._can_serve_stale(cached)
            ):
                return self._result(
                    cached, browser_etag, cache_status="stale", stale=True
                )
            raise self._upstream_error(response)

    async def get_bundle(
        self,
        bundle_id: str,
        *,
        browser_etag: str | None = None,
    ) -> PromptFacadeResult:
        if not _BUNDLE_RE.fullmatch(bundle_id):
            raise PromptRegistryFacadeError(
                400, "Invalid prompt bundle id", headers={"Cache-Control": _NO_STORE}
            )
        client = self._ensure_configured()
        async with self._lock:
            cached = self._bundle_cache.get(bundle_id)
            if cached is not None and self._is_fresh(cached):
                return self._result(cached, browser_etag, cache_status="fresh")
            headers: dict[str, str] = {}
            if cached is not None:
                headers["If-None-Match"] = cached.etag
            try:
                response = await client.get(f"/v1/bundles/{bundle_id}", headers=headers)
            except httpx.RequestError as exc:
                if cached is not None and self._can_serve_stale(cached):
                    return self._result(
                        cached, browser_etag, cache_status="stale", stale=True
                    )
                raise PromptRegistryFacadeError(
                    503,
                    "Prompt registry is temporarily unavailable",
                    headers={"Cache-Control": _NO_STORE, "Retry-After": "1"},
                ) from exc
            if response.status_code == 304:
                if cached is None:
                    raise PromptRegistryFacadeError(
                        502,
                        "Prompt registry returned an unexpected 304",
                        headers={"Cache-Control": _NO_STORE},
                    )
                cached.validated_at = self._clock()
                cached.max_stale_seconds = self._bundle_stale_limits.get(
                    bundle_id, cached.max_stale_seconds
                )
                return self._result(cached, browser_etag, cache_status="revalidated")
            if response.status_code == 200:
                entry = self._validate_bundle(bundle_id, response)
                self._bundle_cache[bundle_id] = entry
                return self._result(entry, browser_etag, cache_status="miss")
            if response.status_code in {404, 410}:
                self._purge_bundle(bundle_id)
                raise self._upstream_error(response)
            if (
                response.status_code >= 500
                and cached is not None
                and self._can_serve_stale(cached)
            ):
                return self._result(
                    cached, browser_etag, cache_status="stale", stale=True
                )
            raise self._upstream_error(response)
