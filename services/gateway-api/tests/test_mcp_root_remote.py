from __future__ import annotations

import asyncio
import contextlib
import hashlib
import socket
from collections.abc import AsyncIterator

import pytest
import uvicorn
from gateway_api.mcp_root_federation import review_root_grant
from gateway_api.mcp_upstream import (
    ActiveRemoteRootSession,
    GatewayUpstreamClientSession,
    UpstreamMcpManager,
    _remote_root_set_sha256,
)
from gateway_api.models import Base, McpRootGrant, McpServer
from mcp import types
from mcp.server import MCPServer
from mcp.server.mcpserver.context import Context
from mcp.server.session import ServerMessageMetadata
from mcp.shared.exceptions import MCPError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextlib.asynccontextmanager
async def _running_root_probe_server() -> AsyncIterator[str]:
    server = MCPServer(name="root-probe-upstream", log_level="WARNING")

    @server.tool()
    async def root_probe(ctx: Context) -> dict[str, object]:
        result = await ctx.request_context.session.send_request(
            types.ListRootsRequest(),
            types.ListRootsResult,
            metadata=ServerMessageMetadata(
                related_request_id=ctx.request_context.request_id
            ),
        )
        return {
            "roots": [str(root.uri) for root in result.roots],
            "names": [str(root.name or "") for root in result.roots],
            "back_channel": True,
        }

    port = _free_port()
    runner = uvicorn.Server(
        uvicorn.Config(
            server.streamable_http_app(
                streamable_http_path="/mcp",
                stateless_http=False,
                json_response=False,
                host="127.0.0.1",
            ),
            host="127.0.0.1",
            port=port,
            lifespan="on",
            log_level="critical",
            timeout_graceful_shutdown=1,
        )
    )
    task = asyncio.create_task(runner.serve())
    try:
        for _ in range(300):
            if runner.started:
                break
            if task.done():
                await task
            await asyncio.sleep(0.01)
        else:
            raise RuntimeError("root probe MCP server did not start")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        runner.should_exit = True
        await asyncio.wait_for(task, timeout=5)


def _server(db: Session, *, owner: str = "tenant-a") -> McpServer:
    server = McpServer(
        id="11111111-1111-4111-8111-111111111111",
        owner_subject=owner,
        origin="gateway",
        display_name="Remote roots fixture",
        normalized_slug="remote-roots-fixture",
        transport="streamable_http",
        endpoint_url="https://mcp.example.test/mcp",
        status="online",
        trust_level="restricted",
        capabilities={},
        catalog_generation=2,
        policy_generation=3,
        version=1,
    )
    db.add(server)
    db.flush([server])
    return server


def _manager(server_id: str) -> UpstreamMcpManager:
    return UpstreamMcpManager(
        public_base_url="https://gateway.example.test",
        gateway_roots_by_server={
            server_id: [{"uri": "file:///srv/project", "name": "Project"}]
        },
    )


def test_gateway_root_config_reconciles_hash_only_persistence() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        server = _server(db)
        manager = _manager(server.id)
        assert manager.configured_gateway_roots(server.id) == [
            {"uri": "file:///srv/project", "name": "Project"}
        ]

        grants = manager.reconcile_configured_gateway_roots(db, server=server)
        assert len(grants) == 1
        grant = grants[0]
        expected_hash = hashlib.sha256(b"file:///srv/project").hexdigest()
        assert grant.root_uri_sha256 == expected_hash
        assert grant.root_uri_hint == f"gateway-root:{expected_hash[:12]}"
        assert grant.root_name == "Project"
        assert grant.runtime_connection_id is None
        assert grant.status == "pending"
        persisted = {
            "root_uri_sha256": grant.root_uri_sha256,
            "root_uri_hint": grant.root_uri_hint,
            "root_name": grant.root_name,
        }
        assert "file:///srv/project" not in repr(persisted)

        grant = review_root_grant(
            db,
            owner_subject=server.owner_subject,
            actor_subject="gateway-admin",
            grant_id=grant.id,
            expected_version=grant.version,
            decision="approved",
        )
        assert grant.status == "approved"
        assert manager._approved_gateway_root_values(db, server=server) == [
            {
                "uri": "file:///srv/project",
                "root_name": "Project",
                "root_uri_sha256": expected_hash,
            }
        ]
        assert "file:///srv/project" not in repr(db.query(McpRootGrant).one().__dict__)


def test_remote_root_change_notification_is_connection_scoped_and_deduplicated() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    class RemoteSession:
        def __init__(self) -> None:
            self.notifications = 0

        async def send_roots_list_changed(self) -> None:
            self.notifications += 1

    with Session(engine) as db:
        server = _server(db)
        manager = _manager(server.id)
        grant = manager.reconcile_configured_gateway_roots(db, server=server)[0]
        session = RemoteSession()
        state = ActiveRemoteRootSession(
            connection_instance_id="connection-a",
            owner_subject=server.owner_subject,
            server_id=server.id,
            policy_generation=server.policy_generation,
            roots=[],
            root_set_sha256=_remote_root_set_sha256([]),
            session=session,
        )
        other_session = RemoteSession()
        other = ActiveRemoteRootSession(
            connection_instance_id="connection-b",
            owner_subject="tenant-b",
            server_id=server.id,
            policy_generation=server.policy_generation,
            roots=[],
            root_set_sha256=_remote_root_set_sha256([]),
            session=other_session,
        )
        manager._active_remote_root_sessions[state.connection_instance_id] = state
        manager._active_remote_root_sessions[other.connection_instance_id] = other

        review_root_grant(
            db,
            owner_subject=server.owner_subject,
            actor_subject="gateway-admin",
            grant_id=grant.id,
            expected_version=grant.version,
            decision="approved",
        )
        assert asyncio.run(manager.notify_root_grant_change(db, server=server)) is True
        assert session.notifications == 1
        assert other_session.notifications == 0
        assert [root["uri"] for root in state.roots] == ["file:///srv/project"]
        first_digest = state.root_set_sha256

        assert asyncio.run(manager.notify_root_grant_change(db, server=server)) is False
        assert session.notifications == 1
        assert state.root_set_sha256 == first_digest

        server.policy_generation += 1
        db.flush([server])
        manager.reconcile_configured_gateway_roots(db, server=server)
        assert db.query(McpRootGrant).one().status == "pending"
        assert asyncio.run(manager.notify_root_grant_change(db, server=server)) is True
        assert session.notifications == 2
        assert state.roots == []
        assert state.policy_generation == server.policy_generation
        assert other_session.notifications == 0


def test_gateway_root_config_rejects_traversal_and_duplicates() -> None:
    with pytest.raises(ValueError, match="Invalid Gateway MCP root config"):
        UpstreamMcpManager(
            public_base_url="https://gateway.example.test",
            gateway_roots_by_server={
                "server-a": [{"uri": "file:///srv/../secret", "name": "Secret"}]
            },
        )

    with pytest.raises(ValueError, match="Duplicate Gateway MCP root config"):
        UpstreamMcpManager(
            public_base_url="https://gateway.example.test",
            gateway_roots_by_server={
                "server-a": [
                    {"uri": "file:///srv/project", "name": "One"},
                    {"uri": "file:///srv/project", "name": "Two"},
                ]
            },
        )


def test_remote_client_session_serves_approved_roots_over_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def legacy_only_discover(self: GatewayUpstreamClientSession):
        del self
        raise MCPError(-32601, "Method not found")

    monkeypatch.setattr(GatewayUpstreamClientSession, "discover", legacy_only_discover)

    async def scenario() -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        try:
            with Session(engine) as db:
                async with _running_root_probe_server() as endpoint:
                    server = _server(db)
                    server.endpoint_url = endpoint
                    db.flush([server])
                    manager = UpstreamMcpManager(
                        public_base_url="https://gateway.example.test",
                        allow_private_networks=True,
                        allow_insecure_http=True,
                        gateway_roots_by_server={
                            server.id: [
                                {"uri": "file:///srv/project", "name": "Project"}
                            ]
                        },
                    )
                    grant = manager.reconcile_configured_gateway_roots(
                        db, server=server
                    )[0]
                    review_root_grant(
                        db,
                        owner_subject=server.owner_subject,
                        actor_subject="gateway-admin",
                        grant_id=grant.id,
                        expected_version=grant.version,
                        decision="approved",
                    )
                    async with manager._session(db, server) as (session, handshake, _):
                        assert handshake.protocolVersion == "2025-11-25"
                        assert session._build_capabilities(handshake.protocolVersion).roots is not None
                        assert len(manager._active_remote_root_sessions) == 1
                        result = await session.call_tool("root_probe", {})
                        assert result.is_error is False
                        assert result.structured_content == {
                            "roots": ["file:///srv/project"],
                            "names": ["Project"],
                            "back_channel": True,
                        }
                    assert manager._active_remote_root_sessions == {}
                    await manager.stop()
        finally:
            engine.dispose()

    asyncio.run(scenario())


def test_modern_remote_session_suppresses_roots_capability() -> None:
    async def scenario() -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        try:
            with Session(engine) as db:
                async with _running_root_probe_server() as endpoint:
                    server = _server(db)
                    server.endpoint_url = endpoint
                    db.flush([server])
                    manager = UpstreamMcpManager(
                        public_base_url="https://gateway.example.test",
                        allow_private_networks=True,
                        allow_insecure_http=True,
                        gateway_roots_by_server={
                            server.id: [
                                {"uri": "file:///srv/project", "name": "Project"}
                            ]
                        },
                    )
                    grant = manager.reconcile_configured_gateway_roots(
                        db, server=server
                    )[0]
                    review_root_grant(
                        db,
                        owner_subject=server.owner_subject,
                        actor_subject="gateway-admin",
                        grant_id=grant.id,
                        expected_version=grant.version,
                        decision="approved",
                    )
                    async with manager._session(db, server) as (session, handshake, _):
                        assert handshake.protocolVersion == "2026-07-28"
                        assert session._build_capabilities(handshake.protocolVersion).roots is None
                        assert manager._active_remote_root_sessions == {}
                        listed = await session.list_tools()
                        assert {tool.name for tool in listed.tools} == {"root_probe"}
                    assert manager._active_remote_root_sessions == {}
                    await manager.stop()
        finally:
            engine.dispose()

    asyncio.run(scenario())
