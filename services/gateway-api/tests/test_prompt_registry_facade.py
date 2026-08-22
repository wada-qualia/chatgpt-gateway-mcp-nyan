from __future__ import annotations

import asyncio
from collections.abc import Callable

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway_api.config import Settings
from gateway_api.prompt_registry_facade import (
    PromptRegistryFacade,
    PromptRegistryFacadeError,
)
from gateway_api.routers import prompt_registry

BUNDLE_ID = "a" * 64
MANIFEST_ETAG = f'"channel:dev:generation:1:sha256:{BUNDLE_ID}"'
BUNDLE_ETAG = f'"sha256:{BUNDLE_ID}"'


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "gateway_prompt_registry_enabled": True,
        "gateway_prompt_registry_base_url": "http://prompt-registry.test",
        "gateway_prompt_registry_service_token": "registry-test-token",
        "gateway_prompt_registry_connect_timeout_seconds": 1.0,
        "gateway_prompt_registry_read_timeout_seconds": 1.0,
        "gateway_prompt_registry_revalidate_after_seconds": 10.0,
        "gateway_prompt_registry_max_stale_seconds": 120,
    }
    values.update(overrides)
    return Settings(**values)


def _manifest(*, max_stale_seconds: int = 60) -> dict[str, object]:
    return {
        "schema_version": 1,
        "channel": "dev",
        "release_id": "release-1",
        "generation": 1,
        "release_generation": 1,
        "bundle_id": BUNDLE_ID,
        "sha256": BUNDLE_ID,
        "etag": MANIFEST_ETAG,
        "cache_scope_id": "global-v1",
        "max_stale_seconds": max_stale_seconds,
    }


def _bundle() -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_id": "release-1",
        "items": [],
        "sha256": BUNDLE_ID,
    }


def _facade(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    clock: list[float] | None = None,
    **settings: object,
) -> PromptRegistryFacade:
    client = httpx.AsyncClient(
        base_url="http://prompt-registry.test",
        headers={"Authorization": "Bearer registry-test-token"},
        transport=httpx.MockTransport(handler),
    )
    return PromptRegistryFacade(
        _settings(**settings),
        client=client,
        clock=(lambda: clock[0]) if clock is not None else (lambda: 0.0),
    )


def test_manifest_fresh_cache_and_browser_304() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.headers["authorization"] == "Bearer registry-test-token"
        return httpx.Response(200, json=_manifest(), headers={"ETag": MANIFEST_ETAG})

    facade = _facade(handler)
    first = asyncio.run(facade.get_manifest("dev"))
    cached = asyncio.run(facade.get_manifest("dev", browser_etag=MANIFEST_ETAG))
    asyncio.run(facade.close())

    assert first.status_code == 200
    assert first.payload is not None
    assert first.payload["cache_scope_id"] == "global-v1"
    assert first.headers["X-Prompt-Cache"] == "miss"
    assert cached.status_code == 304
    assert cached.payload is None
    assert cached.headers["X-Prompt-Cache"] == "fresh"
    assert cached.headers["Cache-Control"] == "private, max-age=0, must-revalidate"
    assert len(calls) == 1


def test_manifest_conditional_upstream_revalidation() -> None:
    clock = [0.0]
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(
                200, json=_manifest(), headers={"ETag": MANIFEST_ETAG}
            )
        assert request.headers["if-none-match"] == MANIFEST_ETAG
        return httpx.Response(304, headers={"ETag": MANIFEST_ETAG})

    facade = _facade(handler, clock=clock)
    asyncio.run(facade.get_manifest("dev"))
    clock[0] = 11.0
    result = asyncio.run(facade.get_manifest("dev"))
    asyncio.run(facade.close())

    assert result.status_code == 200
    assert result.headers["X-Prompt-Cache"] == "revalidated"
    assert len(calls) == 2


def test_manifest_bounded_stale_fallback_and_expiry() -> None:
    clock = [0.0]
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                200,
                json=_manifest(max_stale_seconds=60),
                headers={"ETag": MANIFEST_ETAG},
            )
        raise httpx.ConnectError("registry unavailable", request=request)

    facade = _facade(
        handler, clock=clock, gateway_prompt_registry_revalidate_after_seconds=0
    )
    asyncio.run(facade.get_manifest("dev"))
    clock[0] = 30.0
    stale = asyncio.run(facade.get_manifest("dev"))
    assert stale.status_code == 200
    assert stale.headers["X-Prompt-Cache"] == "stale"
    assert "110" in stale.headers["Warning"]

    clock[0] = 61.0
    with pytest.raises(PromptRegistryFacadeError) as error:
        asyncio.run(facade.get_manifest("dev"))
    asyncio.run(facade.close())
    assert error.value.status_code == 503


def test_known_revocation_purges_manifest_and_bundle_lkg() -> None:
    clock = [0.0]
    manifest_calls = 0
    bundle_calls = 0
    revoked = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal manifest_calls, bundle_calls, revoked
        if request.url.path.endswith("/manifest"):
            manifest_calls += 1
            if revoked:
                return httpx.Response(410, headers={"Cache-Control": "no-store"})
            return httpx.Response(
                200, json=_manifest(), headers={"ETag": MANIFEST_ETAG}
            )
        bundle_calls += 1
        if revoked:
            raise httpx.ConnectError("registry unavailable", request=request)
        return httpx.Response(200, json=_bundle(), headers={"ETag": BUNDLE_ETAG})

    facade = _facade(
        handler, clock=clock, gateway_prompt_registry_revalidate_after_seconds=0
    )
    asyncio.run(facade.get_manifest("dev"))
    asyncio.run(facade.get_bundle(BUNDLE_ID))
    revoked = True
    clock[0] = 20.0

    with pytest.raises(PromptRegistryFacadeError) as revoked_error:
        asyncio.run(facade.get_manifest("dev"))
    assert revoked_error.value.status_code == 410
    assert revoked_error.value.headers["Cache-Control"] == "no-store"

    with pytest.raises(PromptRegistryFacadeError) as unavailable_error:
        asyncio.run(facade.get_bundle(BUNDLE_ID))
    asyncio.run(facade.close())
    assert unavailable_error.value.status_code == 503
    assert manifest_calls == 2
    assert bundle_calls == 2


def test_bundle_integrity_failure_is_fail_closed() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _bundle()
        payload["sha256"] = "b" * 64
        return httpx.Response(200, json=payload, headers={"ETag": BUNDLE_ETAG})

    facade = _facade(handler)
    with pytest.raises(PromptRegistryFacadeError) as error:
        asyncio.run(facade.get_bundle(BUNDLE_ID))
    asyncio.run(facade.close())

    assert error.value.status_code == 502
    assert error.value.headers["Cache-Control"] == "no-store"


def test_bundle_stale_fallback_uses_manifest_limit() -> None:
    clock = [0.0]
    bundle_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal bundle_calls
        if request.url.path.endswith("/manifest"):
            return httpx.Response(
                200,
                json=_manifest(max_stale_seconds=25),
                headers={"ETag": MANIFEST_ETAG},
            )
        bundle_calls += 1
        if bundle_calls == 1:
            return httpx.Response(200, json=_bundle(), headers={"ETag": BUNDLE_ETAG})
        raise httpx.ConnectError("registry unavailable", request=request)

    facade = _facade(
        handler, clock=clock, gateway_prompt_registry_revalidate_after_seconds=0
    )
    asyncio.run(facade.get_manifest("dev"))
    asyncio.run(facade.get_bundle(BUNDLE_ID))
    clock[0] = 20.0
    stale = asyncio.run(facade.get_bundle(BUNDLE_ID, browser_etag=BUNDLE_ETAG))
    assert stale.status_code == 304
    assert stale.headers["X-Prompt-Cache"] == "stale"

    clock[0] = 26.0
    with pytest.raises(PromptRegistryFacadeError) as error:
        asyncio.run(facade.get_bundle(BUNDLE_ID))
    asyncio.run(facade.close())
    assert error.value.status_code == 503


def test_manifest_policy_reduction_tightens_cached_bundle_stale_limit() -> None:
    clock = [0.0]
    manifest_calls = 0
    bundle_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal manifest_calls, bundle_calls
        if request.url.path.endswith("/manifest"):
            manifest_calls += 1
            max_stale = 60 if manifest_calls == 1 else 5
            return httpx.Response(
                200,
                json=_manifest(max_stale_seconds=max_stale),
                headers={"ETag": MANIFEST_ETAG},
            )
        bundle_calls += 1
        if bundle_calls == 1:
            return httpx.Response(200, json=_bundle(), headers={"ETag": BUNDLE_ETAG})
        raise httpx.ConnectError("registry unavailable", request=request)

    facade = _facade(
        handler,
        clock=clock,
        gateway_prompt_registry_revalidate_after_seconds=0,
    )
    asyncio.run(facade.get_manifest("dev"))
    asyncio.run(facade.get_bundle(BUNDLE_ID))
    clock[0] = 10.0
    asyncio.run(facade.get_manifest("dev"))

    with pytest.raises(PromptRegistryFacadeError) as error:
        asyncio.run(facade.get_bundle(BUNDLE_ID))
    asyncio.run(facade.close())

    assert error.value.status_code == 503
    assert manifest_calls == 2
    assert bundle_calls == 2


def test_browser_endpoint_requires_gateway_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway_api import config

    monkeypatch.setenv("GATEWAY_DEV_AUTH", "false")
    config.get_settings.cache_clear()
    app = FastAPI()
    app.state.prompt_registry_facade = _facade(
        lambda _request: httpx.Response(
            200,
            json=_manifest(),
            headers={"ETag": MANIFEST_ETAG},
        )
    )
    app.include_router(prompt_registry.router)
    try:
        with TestClient(app) as client:
            response = client.get("/api/prompts/v1/releases/dev/manifest")
        assert response.status_code == 401
    finally:
        config.get_settings.cache_clear()
        asyncio.run(app.state.prompt_registry_facade.close())


def test_disabled_or_unconfigured_facade_is_fail_closed() -> None:
    facade = PromptRegistryFacade(
        _settings(
            gateway_prompt_registry_enabled=False,
            gateway_prompt_registry_service_token="",
        )
    )
    with pytest.raises(PromptRegistryFacadeError) as error:
        asyncio.run(facade.get_manifest("dev"))
    asyncio.run(facade.close())
    assert error.value.status_code == 503
    assert error.value.headers["Cache-Control"] == "no-store"
