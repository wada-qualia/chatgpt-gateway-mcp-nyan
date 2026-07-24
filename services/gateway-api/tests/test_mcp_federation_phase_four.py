from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from gateway_api.config import get_settings
from gateway_api.models import (
    Base,
    McpInvocation,
    McpRuntimeConnection,
    McpServer,
    McpTool,
    McpToolRevision,
    ThinClient,
)
from gateway_api.thin_client_control import (
    MCP_THIN_CLIENT_CAPABILITIES,
    MCP_THIN_CLIENT_PROTOCOL_VERSION,
    ThinClientConnectionManager,
    ThinClientMcpError,
)
from gateway_api.thin_client_mcp import (
    mark_connection_disconnected,
    reconcile_snapshot,
    register_runtime,
)


class FakeWebSocket:
    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.closed: list[int] = []

    async def send_json(self, payload: dict) -> None:
        self.sent.append(payload)

    async def close(self, *, code: int = 1000) -> None:
        self.closed.append(code)


@pytest.fixture
def db(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GATEWAY_OUTBOX_ENABLED", "false")
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()
    get_settings.cache_clear()


def _client(db: Session) -> ThinClient:
    client = ThinClient(
        id=str(uuid.uuid4()),
        owner_subject="tenant-a",
        hostname="local-runtime",
        directory="/srv/runtime",
        agent_token_hash="hash",
        status="online",
        meta={},
    )
    db.add(client)
    db.commit()
    return client


def _registration(runtime_id: str = "runtime-a") -> dict:
    return {
        "type": "mcp_runtime_registered",
        "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
        "runtime_id": runtime_id,
        "capabilities": sorted(MCP_THIN_CLIENT_CAPABILITIES),
        "servers": [
            {
                "local_server_id": "stdio-a",
                "display_name": "Local Stdio MCP",
                "transport": "stdio",
            }
        ],
    }


def _snapshot(connection_instance_id: str, *, generation: int = 1) -> dict:
    return {
        "type": "mcp_catalog_snapshot",
        "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
        "mcp_protocol_version": "2025-11-25",
        "connection_instance_id": connection_instance_id,
        "runtime_id": "runtime-a",
        "local_server_id": "stdio-a",
        "catalog_generation": generation,
        "tools": [
            {
                "upstream_name": "local_sum",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "left": {"type": "integer"},
                        "right": {"type": "integer"},
                    },
                    "required": ["left", "right"],
                    "additionalProperties": False,
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"total": {"type": "integer"}},
                },
                "title": "Local sum",
                "description": "Read two local values.",
                "annotations": {"readOnlyHint": True},
            }
        ],
    }


def test_exact_connection_fencing_and_unknown_write_outcome() -> None:
    async def scenario() -> None:
        manager = ThinClientConnectionManager()
        first = await manager.register("client-a", FakeWebSocket())
        await manager.register_runtime(
            "client-a",
            first,
            runtime_id="runtime-a",
            protocol_version=MCP_THIN_CLIENT_PROTOCOL_VERSION,
            capabilities=MCP_THIN_CLIENT_CAPABILITIES,
            local_server_ids={"stdio-a"},
        )
        second = await manager.register("client-a", FakeWebSocket())
        stale = await manager.register_runtime(
            "client-a",
            second,
            runtime_id="runtime-a",
            protocol_version=MCP_THIN_CLIENT_PROTOCOL_VERSION,
            capabilities=MCP_THIN_CLIENT_CAPABILITIES,
            local_server_ids={"stdio-a"},
        )
        assert stale == [first]
        assert first.stale is True

        read_task = asyncio.create_task(
            manager.request_mcp(
                "client-a",
                runtime_id="runtime-a",
                local_server_id="stdio-a",
                connection_instance_id=second.connection_instance_id,
                request_id="read-1",
                server_id="server-a",
                revision_id="revision-a",
                tool_name="local_sum",
                schema_hash="a" * 64,
                catalog_generation=1,
                arguments={"left": 1, "right": 2},
                action_class="read",
                timeout_seconds=3,
            )
        )
        await asyncio.sleep(0)
        assert second.websocket.sent[-1]["type"] == "mcp_call"
        assert (
            await manager.complete_mcp(
                "client-a",
                first,
                {
                    "type": "mcp_call_result",
                    "connection_instance_id": first.connection_instance_id,
                    "runtime_id": "runtime-a",
                    "local_server_id": "stdio-a",
                    "request_id": "read-1",
                },
            )
            is False
        )
        response = {
            "type": "mcp_call_result",
            "connection_instance_id": second.connection_instance_id,
            "runtime_id": "runtime-a",
            "local_server_id": "stdio-a",
            "request_id": "read-1",
        }
        assert await manager.complete_mcp("client-a", second, response) is True
        assert await read_task == response

        write_task = asyncio.create_task(
            manager.request_mcp(
                "client-a",
                runtime_id="runtime-a",
                local_server_id="stdio-a",
                connection_instance_id=second.connection_instance_id,
                request_id="write-1",
                server_id="server-a",
                revision_id="revision-b",
                tool_name="publish",
                schema_hash="b" * 64,
                catalog_generation=1,
                arguments={"version": "1.0.0"},
                action_class="write",
                timeout_seconds=3,
                idempotency_key="publish-1",
            )
        )
        await asyncio.sleep(0)
        await manager.unregister("client-a", second)
        with pytest.raises(ThinClientMcpError) as captured:
            await write_task
        assert captured.value.code == "MCP_CONNECTION_LOST"
        assert captured.value.unknown_outcome is True
        assert captured.value.retryable is False

    asyncio.run(scenario())


def test_runtime_registration_reconnect_and_transactional_catalog(db: Session) -> None:
    client = _client(db)
    manager = ThinClientConnectionManager()
    first = asyncio.run(manager.register(client.id, FakeWebSocket()))
    message = _registration()
    asyncio.run(
        manager.register_runtime(
            client.id,
            first,
            runtime_id="runtime-a",
            protocol_version=MCP_THIN_CLIENT_PROTOCOL_VERSION,
            capabilities=MCP_THIN_CLIENT_CAPABILITIES,
            local_server_ids={"stdio-a"},
        )
    )
    acknowledgement = register_runtime(
        db,
        owner_subject="tenant-a",
        client_id=client.id,
        connection=first,
        message=message,
    )
    server_id = acknowledgement["servers"][0]["server_id"]
    server = db.get(McpServer, server_id)
    assert server.origin == "thin_client"
    assert server.endpoint_url is None
    assert server.local_server_id == "stdio-a"

    result = reconcile_snapshot(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        client_id=client.id,
        connection=first,
        message=_snapshot(first.connection_instance_id),
        max_tools=50,
    )
    assert result["gateway_catalog_generation"] == 1
    tool = db.query(McpTool).filter(McpTool.server_id == server_id).one()
    revision = db.get(McpToolRevision, tool.current_revision_id)
    assert revision.schema_hash

    invalid = _snapshot(first.connection_instance_id, generation=2)
    invalid["tools"][0]["input_schema"] = {"type": "not-valid"}
    with pytest.raises(Exception):
        reconcile_snapshot(
            db,
            owner_subject="tenant-a",
            actor_subject="tenant-a",
            client_id=client.id,
            connection=first,
            message=invalid,
            max_tools=50,
        )
    db.expire_all()
    assert db.get(McpServer, server_id).catalog_generation == 1

    second = asyncio.run(manager.register(client.id, FakeWebSocket()))
    stale = asyncio.run(
        manager.register_runtime(
            client.id,
            second,
            runtime_id="runtime-a",
            protocol_version=MCP_THIN_CLIENT_PROTOCOL_VERSION,
            capabilities=MCP_THIN_CLIENT_CAPABILITIES,
            local_server_ids={"stdio-a"},
        )
    )
    assert stale == [first]
    second_ack = register_runtime(
        db,
        owner_subject="tenant-a",
        client_id=client.id,
        connection=second,
        message=message,
    )
    assert second_ack["servers"][0]["server_id"] == server_id
    runtime_states = {
        item.connection_instance_id: item.state
        for item in db.query(McpRuntimeConnection)
        .filter(McpRuntimeConnection.server_id == server_id)
        .all()
    }
    assert runtime_states[first.connection_instance_id] == "stale"
    assert runtime_states[second.connection_instance_id] == "online"


def test_disconnect_marks_only_dispatched_write_unknown(db: Session) -> None:
    client = _client(db)
    manager = ThinClientConnectionManager()
    connection = asyncio.run(manager.register(client.id, FakeWebSocket()))
    message = _registration()
    asyncio.run(
        manager.register_runtime(
            client.id,
            connection,
            runtime_id="runtime-a",
            protocol_version=MCP_THIN_CLIENT_PROTOCOL_VERSION,
            capabilities=MCP_THIN_CLIENT_CAPABILITIES,
            local_server_ids={"stdio-a"},
        )
    )
    acknowledgement = register_runtime(
        db,
        owner_subject="tenant-a",
        client_id=client.id,
        connection=connection,
        message=message,
    )
    server_id = acknowledgement["servers"][0]["server_id"]
    reconcile_snapshot(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        client_id=client.id,
        connection=connection,
        message=_snapshot(connection.connection_instance_id),
        max_tools=50,
    )
    tool = db.query(McpTool).filter(McpTool.server_id == server_id).one()
    revision = db.get(McpToolRevision, tool.current_revision_id)
    runtime = (
        db.query(McpRuntimeConnection)
        .filter(
            McpRuntimeConnection.server_id == server_id,
            McpRuntimeConnection.connection_instance_id
            == connection.connection_instance_id,
        )
        .one()
    )
    invocation = McpInvocation(
        id=str(uuid.uuid4()),
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        server_id=server_id,
        tool_id=tool.id,
        revision_id=revision.id,
        schema_hash=revision.schema_hash,
        action_class="write",
        arguments_redacted={"keys": ["version"]},
        arguments_sha256="c" * 64,
        runtime_connection_id=runtime.id,
        connection_instance_id=connection.connection_instance_id,
        thin_client_request_id="write-request-1",
        outcome="running",
        unknown_outcome=False,
    )
    db.add(invocation)
    db.commit()
    mark_connection_disconnected(
        db,
        owner_subject="tenant-a",
        client_id=client.id,
        connection=connection,
    )
    db.refresh(invocation)
    assert invocation.outcome == "unknown"
    assert invocation.unknown_outcome is True
    assert invocation.normalized_error_code == "MCP_CONNECTION_LOST"


def test_upstream_manager_routes_exact_revision_through_thin_client(
    db: Session,
) -> None:
    from types import SimpleNamespace

    from gateway_api.mcp_upstream import UpstreamMcpManager

    client = _client(db)
    connection_instance_id = "connection-exact-a"

    class FakeThinTransport:
        def __init__(self) -> None:
            self.calls: list[dict] = []
            self.connection = SimpleNamespace(
                connection_instance_id=connection_instance_id
            )

        def active_mcp_connection(
            self, client_id: str, *, runtime_id: str, local_server_id: str
        ):
            assert client_id == client.id
            assert runtime_id == "runtime-a"
            assert local_server_id == "stdio-a"
            return self.connection

        async def request_mcp(self, client_id: str, **kwargs):
            self.calls.append({"client_id": client_id, **kwargs})
            return {
                "type": "mcp_call_result",
                "connection_instance_id": connection_instance_id,
                "runtime_id": "runtime-a",
                "local_server_id": "stdio-a",
                "request_id": kwargs["request_id"],
                "schema_hash": kwargs["schema_hash"],
                "catalog_generation": kwargs["catalog_generation"],
                "result": {
                    "content": [{"type": "text", "text": "3"}],
                    "structuredContent": {"total": 3},
                    "isError": False,
                },
            }

    transport = FakeThinTransport()
    manager = ThinClientConnectionManager()
    connection = asyncio.run(manager.register(client.id, FakeWebSocket()))
    connection.connection_instance_id = connection_instance_id
    message = _registration()
    asyncio.run(
        manager.register_runtime(
            client.id,
            connection,
            runtime_id="runtime-a",
            protocol_version=MCP_THIN_CLIENT_PROTOCOL_VERSION,
            capabilities=MCP_THIN_CLIENT_CAPABILITIES,
            local_server_ids={"stdio-a"},
        )
    )
    acknowledgement = register_runtime(
        db,
        owner_subject="tenant-a",
        client_id=client.id,
        connection=connection,
        message=message,
    )
    server_id = acknowledgement["servers"][0]["server_id"]
    reconcile_snapshot(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        client_id=client.id,
        connection=connection,
        message=_snapshot(connection_instance_id),
        max_tools=50,
    )
    tool = db.query(McpTool).filter(McpTool.server_id == server_id).one()
    revision = db.get(McpToolRevision, tool.current_revision_id)

    upstream = UpstreamMcpManager(
        public_base_url="https://gateway.example.test",
        thin_client_transport=transport,
    )
    result = asyncio.run(
        upstream.call_exact_revision(
            db,
            owner_subject="tenant-a",
            actor_subject="tenant-a",
            revision_id=revision.id,
            arguments={"left": 1, "right": 2},
            gateway_tool_call_id="gateway-call-a",
            correlation_id="correlation-a",
        )
    )
    assert result.payload["structuredContent"] == {"total": 3}
    assert len(transport.calls) == 1
    sent = transport.calls[0]
    assert sent["server_id"] == server_id
    assert sent["revision_id"] == revision.id
    assert sent["schema_hash"] == revision.schema_hash
    assert sent["catalog_generation"] == revision.catalog_generation
    assert sent["connection_instance_id"] == connection_instance_id
    invocation = db.get(McpInvocation, result.invocation_id)
    assert invocation.runtime_connection_id is not None
    assert invocation.connection_instance_id == connection_instance_id
    assert invocation.thin_client_request_id == sent["request_id"]
    assert invocation.outcome == "succeeded"


def test_thin_client_protocol_schema_rejects_gateway_process_overrides() -> None:
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator

    root = Path(__file__).resolve().parents[3]
    schema = json.loads(
        (root / "schemas/gateway.mcp.thin_client_protocol.v1.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    call = {
        "type": "mcp_call",
        "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
        "request_id": "request-a",
        "connection_instance_id": str(uuid.uuid4()),
        "runtime_id": "runtime-a",
        "local_server_id": "stdio-a",
        "server_id": str(uuid.uuid4()),
        "revision_id": str(uuid.uuid4()),
        "tool_name": "local_sum",
        "schema_hash": "a" * 64,
        "catalog_generation": 1,
        "arguments": {"left": 1, "right": 2},
        "action_class": "read",
        "idempotency_key": None,
    }
    validator.validate(call)
    for forbidden_name, forbidden_value in (
        ("command", "/bin/sh"),
        ("args", ["-c", "unsafe"]),
        ("cwd", "/tmp"),
        ("environment", {"TOKEN": "secret"}),
        ("url", "http://127.0.0.1:9000/mcp"),
        ("headers", {"Authorization": "secret"}),
    ):
        invalid = {**call, forbidden_name: forbidden_value}
        assert not validator.is_valid(invalid)


def test_thin_client_runtime_cannot_impersonate_another_tenant(db: Session) -> None:
    client = _client(db)
    manager = ThinClientConnectionManager()
    connection = asyncio.run(manager.register(client.id, FakeWebSocket()))
    asyncio.run(
        manager.register_runtime(
            client.id,
            connection,
            runtime_id="runtime-a",
            protocol_version=MCP_THIN_CLIENT_PROTOCOL_VERSION,
            capabilities=MCP_THIN_CLIENT_CAPABILITIES,
            local_server_ids={"stdio-a"},
        )
    )
    with pytest.raises(ThinClientMcpError) as captured:
        register_runtime(
            db,
            owner_subject="tenant-b",
            client_id=client.id,
            connection=connection,
            message=_registration(),
        )
    assert captured.value.code == "MCP_SERVER_OFFLINE"
    assert db.query(McpServer).count() == 0
