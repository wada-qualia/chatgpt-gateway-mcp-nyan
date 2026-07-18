from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from gateway_api.thin_client_control import ThinClientConnectionManager
from gateway_api.routers.thin_clients import _websocket_bearer_token


class CompletingWebSocket:
    def __init__(self, manager: ThinClientConnectionManager, name: str) -> None:
        self.manager = manager
        self.name = name
        self.closed_codes: list[int] = []

    async def send_json(self, payload: dict) -> None:
        await self.manager.complete(
            str(payload["request_id"]),
            {"ok": True, "result": {"connection": self.name}},
        )

    async def close(self, code: int) -> None:
        self.closed_codes.append(code)


class BlockingWebSocket:
    def __init__(self) -> None:
        self.sent = asyncio.Event()
        self.closed_codes: list[int] = []

    async def send_json(self, payload: dict) -> None:
        self.sent.set()

    async def close(self, code: int) -> None:
        self.closed_codes.append(code)


def test_websocket_bearer_header_takes_precedence_over_legacy_query_token() -> None:
    websocket = type("HeaderWebSocket", (), {"headers": {"authorization": "Bearer header-token"}})()

    assert _websocket_bearer_token(websocket, "query-token") == "header-token"
    assert _websocket_bearer_token(type("LegacyWebSocket", (), {"headers": {}})(), "query-token") == "query-token"


def test_manager_reports_live_connection_presence() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        assert manager.is_connected("client-1") is False
        connection = await manager.register("client-1", CompletingWebSocket(manager, "first"))
        assert manager.is_connected("client-1") is True
        await manager.unregister("client-1", connection)
        assert manager.is_connected("client-1") is False

    asyncio.run(scenario())


def test_manager_routes_different_client_ids_independently() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        await manager.register("client-1", CompletingWebSocket(manager, "first"))
        await manager.register("client-2", CompletingWebSocket(manager, "second"))

        first, second = await asyncio.gather(
            manager.request("client-1", tool="list_files", arguments={}, timeout_seconds=1),
            manager.request("client-2", tool="list_files", arguments={}, timeout_seconds=1),
        )

        assert first["result"]["connection"] == "first"
        assert second["result"]["connection"] == "second"

    asyncio.run(scenario())


def test_manager_keeps_same_client_id_online_until_last_connection_closes() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        old_connection = await manager.register("client-1", CompletingWebSocket(manager, "old"))
        new_connection = await manager.register("client-1", CompletingWebSocket(manager, "new"))

        newest_result = await manager.request("client-1", tool="list_files", arguments={}, timeout_seconds=1)
        assert newest_result["result"]["connection"] == "new"

        assert await manager.unregister("client-1", new_connection) is False
        fallback_result = await manager.request("client-1", tool="list_files", arguments={}, timeout_seconds=1)
        assert fallback_result["result"]["connection"] == "old"

        assert await manager.unregister("client-1", old_connection) is True
        with pytest.raises(HTTPException) as exc_info:
            await manager.request("client-1", tool="list_files", arguments={}, timeout_seconds=1)
        assert exc_info.value.status_code == 409
        assert exc_info.value.detail == "Thin client is not connected"

    asyncio.run(scenario())


def test_stale_connection_disconnect_fails_only_its_pending_requests() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        old_websocket = BlockingWebSocket()
        old_connection = await manager.register("client-1", old_websocket)
        old_request = asyncio.create_task(
            manager.request("client-1", tool="run_command", arguments={"command": "sleep 10"}, timeout_seconds=5)
        )
        await old_websocket.sent.wait()

        await manager.register("client-1", CompletingWebSocket(manager, "new"))
        assert await manager.unregister("client-1", old_connection) is False

        with pytest.raises(HTTPException) as exc_info:
            await old_request
        assert exc_info.value.status_code == 409
        assert "Thin client disconnected: client-1" in str(exc_info.value.detail)

        new_result = await manager.request("client-1", tool="list_files", arguments={}, timeout_seconds=1)
        assert new_result["result"]["connection"] == "new"

    asyncio.run(scenario())


def test_disconnect_closes_every_connection_for_client_id() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        first = CompletingWebSocket(manager, "first")
        second = CompletingWebSocket(manager, "second")
        await manager.register("client-1", first)
        await manager.register("client-1", second)

        await manager.disconnect("client-1", code=4001)

        assert first.closed_codes == [4001]
        assert second.closed_codes == [4001]
        with pytest.raises(HTTPException) as exc_info:
            await manager.request("client-1", tool="list_files", arguments={}, timeout_seconds=1)
        assert exc_info.value.status_code == 409

    asyncio.run(scenario())
