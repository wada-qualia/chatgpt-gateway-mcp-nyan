from __future__ import annotations

import asyncio
import hashlib
import uuid
from typing import Any

import pytest
from gateway_api.config import get_settings
from gateway_api.mcp_root_federation import review_root_grant
from gateway_api.models import Base, McpRootGrant, McpRuntimeConnection, ThinClient
from gateway_api.thin_client_control import (
    MCP_THIN_CLIENT_PROTOCOL_VERSION,
    ThinClientConnectionManager,
    ThinClientMcpError,
)
from gateway_api.thin_client_mcp import record_roots_update_ack, register_runtime
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


class FakeWebSocket:
    async def send_json(self, _payload: dict[str, Any]) -> None:
        return None


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
        hostname="runtime-host",
        directory="C:/runtime",
        agent_token_hash="hash",
        status="online",
        meta={},
    )
    db.add(client)
    db.commit()
    return client


def _registration(root_hash: str) -> dict[str, Any]:
    return {
        "type": "mcp_runtime_registered",
        "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
        "runtime_id": "runtime-a",
        "capabilities": ["mcp_runtime_v1", "mcp_roots_v1"],
        "servers": [
            {
                "local_server_id": "stdio-a",
                "display_name": "Local Stdio MCP",
                "transport": "stdio",
                "roots": [
                    {
                        "root_uri_sha256": root_hash,
                        "root_uri_hint": f"local-root:{root_hash[:12]}",
                        "root_name": "Workspace",
                    }
                ],
            }
        ],
    }


def _connection(manager: ThinClientConnectionManager, client_id: str):
    connection = asyncio.run(manager.register(client_id, FakeWebSocket()))
    asyncio.run(
        manager.register_runtime(
            client_id,
            connection,
            runtime_id="runtime-a",
            protocol_version=MCP_THIN_CLIENT_PROTOCOL_VERSION,
            capabilities={"mcp_runtime_v1", "mcp_roots_v1"},
            local_server_ids={"stdio-a"},
        )
    )
    return connection


def test_registration_creates_pending_hash_only_grant_and_syncs_after_review(db: Session) -> None:
    client = _client(db)
    manager = ThinClientConnectionManager()
    connection = _connection(manager, client.id)
    root_hash = hashlib.sha256(b"file:///C:/workspace").hexdigest()
    registration = _registration(root_hash)

    first = register_runtime(
        db,
        owner_subject="tenant-a",
        client_id=client.id,
        connection=connection,
        message=registration,
    )
    grant = db.query(McpRootGrant).one()
    assert grant.status == "pending"
    assert grant.root_uri_sha256 == root_hash
    assert grant.root_uri_hint == f"local-root:{root_hash[:12]}"
    assert first["servers"][0]["_root_update"]["roots"] == []
    assert "file:" not in repr(first)

    review_root_grant(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        grant_id=grant.id,
        expected_version=grant.version,
        decision="approved",
    )
    second = register_runtime(
        db,
        owner_subject="tenant-a",
        client_id=client.id,
        connection=connection,
        message=registration,
    )
    update = second["servers"][0]["_root_update"]
    assert update["roots"] == [
        {
            "root_uri_sha256": root_hash,
            "root_name": "Workspace",
            "version": grant.version,
        }
    ]
    assert "file:" not in repr(update)

    record_roots_update_ack(
        db,
        owner_subject="tenant-a",
        client_id=client.id,
        connection=connection,
        message={
            "type": "mcp_roots_update_ack",
            "connection_instance_id": connection.connection_instance_id,
            "runtime_id": "runtime-a",
            "local_server_id": "stdio-a",
            "server_id": update["server_id"],
            "policy_generation": update["policy_generation"],
            "root_set_sha256": update["root_set_sha256"],
        },
    )
    runtime = (
        db.query(McpRuntimeConnection)
        .filter(
            McpRuntimeConnection.connection_instance_id == connection.connection_instance_id
        )
        .one()
    )
    assert runtime.meta["roots_ack"]["root_set_sha256"] == update["root_set_sha256"]


def test_reconnect_forces_root_reapproval(db: Session) -> None:
    client = _client(db)
    manager = ThinClientConnectionManager()
    first_connection = _connection(manager, client.id)
    root_hash = "a" * 64
    registration = _registration(root_hash)
    first = register_runtime(
        db,
        owner_subject="tenant-a",
        client_id=client.id,
        connection=first_connection,
        message=registration,
    )
    grant = db.query(McpRootGrant).one()
    review_root_grant(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        grant_id=grant.id,
        expected_version=grant.version,
        decision="approved",
    )
    assert first["servers"][0]["_root_update"]["roots"] == []

    second_connection = _connection(manager, client.id)
    second = register_runtime(
        db,
        owner_subject="tenant-a",
        client_id=client.id,
        connection=second_connection,
        message=registration,
    )
    db.refresh(grant)
    assert grant.status == "pending"
    assert grant.runtime_connection_id != first_connection.connection_instance_id
    assert second["servers"][0]["_root_update"]["roots"] == []


def test_registration_rejects_root_path_material_and_missing_capability(db: Session) -> None:
    client = _client(db)
    manager = ThinClientConnectionManager()
    connection = _connection(manager, client.id)
    message = _registration("b" * 64)
    message["servers"][0]["roots"][0]["path"] = "C:/secret"
    with pytest.raises(ThinClientMcpError, match="unsupported fields"):
        register_runtime(
            db,
            owner_subject="tenant-a",
            client_id=client.id,
            connection=connection,
            message=message,
        )

    missing_capability = _registration("c" * 64)
    missing_capability["capabilities"] = ["mcp_runtime_v1"]
    with pytest.raises(ThinClientMcpError, match="mcp_roots_v1"):
        register_runtime(
            db,
            owner_subject="tenant-a",
            client_id=client.id,
            connection=connection,
            message=missing_capability,
        )
