from __future__ import annotations

import asyncio
from typing import Any

import pytest
from gateway_api.routers.thin_clients import _mcp_notification_refresh_message
from gateway_api.thin_client_control import (
    MCP_THIN_CLIENT_PROTOCOL_VERSION,
    ThinClientConnection,
    ThinClientConnectionManager,
    ThinClientMcpError,
)


class _BlockingWebSocket:
    def __init__(self) -> None:
        self.sent = asyncio.Event()
        self.payloads: list[dict[str, Any]] = []

    async def send_json(self, payload: dict[str, Any]) -> None:
        self.payloads.append(dict(payload))
        self.sent.set()


async def _registered(
    manager: ThinClientConnectionManager,
    websocket: _BlockingWebSocket,
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


def _base(connection: ThinClientConnection, request_id: str) -> dict[str, Any]:
    return {
        "runtime_id": "runtime-1",
        "local_server_id": "local-server-1",
        "connection_instance_id": connection.connection_instance_id,
        "request_id": request_id,
        "server_id": "server-1",
        "entity_id": "entity-1",
        "revision_id": "revision-1",
        "schema_hash": "a" * 64,
        "catalog_generation": 7,
        "timeout_seconds": 1.0,
    }


def test_prompt_request_is_hash_only_and_terminal_type_fenced() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        websocket = _BlockingWebSocket()
        connection = await _registered(
            manager,
            websocket,
            {"mcp_runtime_v1", "mcp_prompts_v1"},
        )
        task = asyncio.create_task(
            manager.request_mcp_prompt(
                "client-1",
                **_base(connection, "prompt-1"),
                prompt_name_sha256="b" * 64,
                arguments={"environment": "prod"},
            )
        )
        await websocket.sent.wait()
        payload = websocket.payloads[-1]
        assert payload["type"] == "mcp_prompt_get"
        assert payload["prompt_name_sha256"] == "b" * 64
        assert payload["arguments"] == {"environment": "prod"}
        for forbidden in ("prompt_name", "name", "uri", "url", "headers", "command"):
            assert forbidden not in payload

        forged = {
            "type": "mcp_call_result",
            "request_id": payload["request_id"],
            "connection_instance_id": connection.connection_instance_id,
            "runtime_id": "runtime-1",
            "local_server_id": "local-server-1",
        }
        assert await manager.complete_mcp("client-1", connection, forged) is False
        assert task.done() is False
        exact = {**forged, "type": "mcp_prompt_get_result", "result": {"messages": []}}
        assert await manager.complete_mcp("client-1", connection, exact) is True
        result = await task
        assert result["type"] == "mcp_prompt_get_result"

    asyncio.run(scenario())


def test_prompt_and_completion_require_negotiated_capabilities() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        websocket = _BlockingWebSocket()
        connection = await _registered(manager, websocket, {"mcp_runtime_v1"})
        with pytest.raises(ThinClientMcpError) as prompt_error:
            await manager.request_mcp_prompt(
                "client-1",
                **_base(connection, "prompt-2"),
                prompt_name_sha256="b" * 64,
                arguments={},
            )
        assert prompt_error.value.code == "MCP_PROTOCOL_MISMATCH"
        with pytest.raises(ThinClientMcpError) as completion_error:
            await manager.request_mcp_completion(
                "client-1",
                **_base(connection, "completion-1"),
                ref_kind="prompt",
                ref_key_sha256="b" * 64,
                argument={"name": "environment", "value": "pr"},
                context_arguments={},
            )
        assert completion_error.value.code == "MCP_PROTOCOL_MISMATCH"
        assert websocket.payloads == []

    asyncio.run(scenario())


def test_completion_request_carries_only_exact_hash_reference() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        websocket = _BlockingWebSocket()
        connection = await _registered(
            manager,
            websocket,
            {"mcp_runtime_v1", "mcp_completion_v1"},
        )
        task = asyncio.create_task(
            manager.request_mcp_completion(
                "client-1",
                **_base(connection, "completion-2"),
                ref_kind="prompt",
                ref_key_sha256="b" * 64,
                argument={"name": "environment", "value": "pr"},
                context_arguments={"summary": "release"},
            )
        )
        await websocket.sent.wait()
        payload = websocket.payloads[-1]
        assert payload["type"] == "mcp_completion"
        assert payload["ref_kind"] == "prompt"
        assert payload["ref_key_sha256"] == "b" * 64
        for forbidden in ("ref", "prompt_name", "name", "uri", "uriTemplate", "url", "headers"):
            assert forbidden not in payload
        exact = {
            "type": "mcp_completion_result",
            "request_id": payload["request_id"],
            "connection_instance_id": connection.connection_instance_id,
            "runtime_id": "runtime-1",
            "local_server_id": "local-server-1",
            "result": {"completion": {"values": []}},
        }
        assert await manager.complete_mcp("client-1", connection, exact) is True
        result = await task
        assert result["type"] == "mcp_completion_result"

    asyncio.run(scenario())


def test_prompt_list_changed_notification_builds_exact_refresh_envelope() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        websocket = _BlockingWebSocket()
        connection = await _registered(
            manager, websocket, {"mcp_runtime_v1", "mcp_prompts_v1"}
        )
        message = {
            "type": "mcp_notification",
            "connection_instance_id": connection.connection_instance_id,
            "runtime_id": "runtime-1",
            "local_server_id": "local-server-1",
            "method": "notifications/prompts/list_changed",
        }
        assert _mcp_notification_refresh_message(connection, message) == {
            "type": "mcp_refresh_catalog",
            "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
            "connection_instance_id": connection.connection_instance_id,
            "runtime_id": "runtime-1",
            "local_server_id": "local-server-1",
            "reason": "prompts_list_changed",
        }
        forged = dict(message, local_server_id="foreign-server")
        with pytest.raises(ThinClientMcpError) as exc_info:
            _mcp_notification_refresh_message(connection, forged)
        assert exc_info.value.code == "MCP_STALE_CONNECTION"

    asyncio.run(scenario())
