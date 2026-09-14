from __future__ import annotations

import asyncio
from typing import Any

import pytest
from gateway_api.thin_client_control import (
    MCP_THIN_CLIENT_PROTOCOL_VERSION,
    ThinClientConnection,
    ThinClientConnectionManager,
    ThinClientMcpError,
)


class _ResourceCompletingWebSocket:
    def __init__(self, manager: ThinClientConnectionManager) -> None:
        self.manager = manager
        self.connection: ThinClientConnection | None = None
        self.sent: list[dict[str, Any]] = []

    async def send_json(self, payload: dict[str, Any]) -> None:
        self.sent.append(dict(payload))
        assert self.connection is not None
        completed = await self.manager.complete_mcp(
            "client-1",
            self.connection,
            {
                "type": "mcp_resource_read_result",
                "request_id": payload["request_id"],
                "connection_instance_id": payload["connection_instance_id"],
                "runtime_id": payload["runtime_id"],
                "local_server_id": payload["local_server_id"],
                "schema_hash": payload["schema_hash"],
                "catalog_generation": payload["catalog_generation"],
                "descriptor": {"uri_sha256": payload["uri_sha256"]},
                "result": {"contents": []},
                "mcp_protocol_version": "2025-11-25",
            },
        )
        assert completed is True


class _BlockingResourceWebSocket:
    def __init__(self) -> None:
        self.sent = asyncio.Event()
        self.payload: dict[str, Any] | None = None

    async def send_json(self, payload: dict[str, Any]) -> None:
        self.payload = dict(payload)
        self.sent.set()


async def _registered_resource_connection(
    manager: ThinClientConnectionManager,
    websocket: Any,
    *,
    capabilities: set[str],
) -> ThinClientConnection:
    connection = await manager.register("client-1", websocket)
    await manager.register_runtime(
        "client-1",
        connection,
        runtime_id="runtime-1",
        protocol_version=MCP_THIN_CLIENT_PROTOCOL_VERSION,
        capabilities=capabilities,
        local_server_ids={"local-server-1"},
    )
    return connection


def _request_kwargs(connection: ThinClientConnection) -> dict[str, Any]:
    return {
        "runtime_id": "runtime-1",
        "local_server_id": "local-server-1",
        "connection_instance_id": connection.connection_instance_id,
        "request_id": "31111111-1111-4111-8111-111111111111",
        "server_id": "41111111-1111-4111-8111-111111111111",
        "entity_kind": "resource_template",
        "entity_id": "51111111-1111-4111-8111-111111111111",
        "revision_id": "61111111-1111-4111-8111-111111111111",
        "schema_hash": "a" * 64,
        "uri_sha256": "b" * 64,
        "catalog_generation": 7,
        "arguments": {"document_id": "42"},
        "timeout_seconds": 1.0,
    }


def test_resource_request_routes_only_exact_hash_and_revision_evidence() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        websocket = _ResourceCompletingWebSocket(manager)
        connection = await _registered_resource_connection(
            manager,
            websocket,
            capabilities={"mcp_runtime_v1", "mcp_resources_v1"},
        )
        websocket.connection = connection

        result = await manager.request_mcp_resource(
            "client-1", **_request_kwargs(connection)
        )

        assert result["type"] == "mcp_resource_read_result"
        assert len(websocket.sent) == 1
        payload = websocket.sent[0]
        assert payload["type"] == "mcp_resource_read"
        assert payload["connection_instance_id"] == connection.connection_instance_id
        assert payload["revision_id"] == _request_kwargs(connection)["revision_id"]
        assert payload["schema_hash"] == "a" * 64
        assert payload["uri_sha256"] == "b" * 64
        assert payload["catalog_generation"] == 7
        assert payload["arguments"] == {"document_id": "42"}
        assert "uri" not in payload
        assert "upstream_uri" not in payload
        assert "endpoint_url" not in payload

    asyncio.run(scenario())


def test_resource_request_requires_negotiated_resource_capability() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        websocket = _BlockingResourceWebSocket()
        connection = await _registered_resource_connection(
            manager,
            websocket,
            capabilities={"mcp_runtime_v1"},
        )

        with pytest.raises(ThinClientMcpError) as exc_info:
            await manager.request_mcp_resource(
                "client-1", **_request_kwargs(connection)
            )
        assert exc_info.value.code == "MCP_PROTOCOL_MISMATCH"
        assert exc_info.value.http_status == 422
        assert websocket.payload is None

    asyncio.run(scenario())


def test_resource_request_rejects_stale_connection_instance_before_dispatch() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        websocket = _BlockingResourceWebSocket()
        connection = await _registered_resource_connection(
            manager,
            websocket,
            capabilities={"mcp_runtime_v1", "mcp_resources_v1"},
        )
        kwargs = _request_kwargs(connection)
        kwargs["connection_instance_id"] = "stale-instance"

        with pytest.raises(ThinClientMcpError) as exc_info:
            await manager.request_mcp_resource("client-1", **kwargs)
        assert exc_info.value.code == "MCP_STALE_CONNECTION"
        assert exc_info.value.http_status == 409
        assert websocket.payload is None

    asyncio.run(scenario())


def test_forged_resource_result_cannot_complete_exact_pending_request() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        websocket = _BlockingResourceWebSocket()
        connection = await _registered_resource_connection(
            manager,
            websocket,
            capabilities={"mcp_runtime_v1", "mcp_resources_v1"},
        )
        kwargs = _request_kwargs(connection)
        task = asyncio.create_task(manager.request_mcp_resource("client-1", **kwargs))
        await websocket.sent.wait()
        assert websocket.payload is not None
        payload = websocket.payload

        forged = {
            "type": "mcp_resource_read_result",
            "request_id": payload["request_id"],
            "connection_instance_id": "forged-instance",
            "runtime_id": payload["runtime_id"],
            "local_server_id": payload["local_server_id"],
            "schema_hash": payload["schema_hash"],
            "catalog_generation": payload["catalog_generation"],
            "descriptor": {"uri_sha256": payload["uri_sha256"]},
            "result": {"contents": []},
        }
        assert await manager.complete_mcp("client-1", connection, forged) is False
        assert task.done() is False

        exact = dict(forged)
        exact["connection_instance_id"] = connection.connection_instance_id
        assert await manager.complete_mcp("client-1", connection, exact) is True
        result = await task
        assert result["request_id"] == payload["request_id"]

    asyncio.run(scenario())
