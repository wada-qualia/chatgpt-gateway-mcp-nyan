from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gateway_api.auth import get_current_user
from gateway_api.config import get_settings
from gateway_api.database import get_db
from gateway_api.mcp_upstream import UpstreamMcpManager
from gateway_api.models import Base, McpRootGrant, McpServer, User
from gateway_api.routers.mcp_federation import router as federation_router
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


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


def _server(db: Session, *, origin: str = "gateway") -> McpServer:
    thin = origin == "thin_client"
    server = McpServer(
        id=(
            "11111111-1111-4111-8111-111111111111"
            if not thin
            else "22222222-2222-4222-8222-222222222222"
        ),
        owner_subject="tenant-a",
        origin=origin,
        thin_client_id=("33333333-3333-4333-8333-333333333333" if thin else None),
        runtime_id=("runtime-a" if thin else None),
        local_server_id=("local-a" if thin else None),
        display_name="Root API fixture",
        normalized_slug=("root-api-fixture" if not thin else "root-api-thin-fixture"),
        transport=("stdio" if thin else "streamable_http"),
        endpoint_url=(None if thin else "https://mcp.example.test/mcp"),
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


def _client(
    db: Session,
    manager: UpstreamMcpManager,
) -> tuple[TestClient, dict[str, User]]:
    app = FastAPI()
    app.state.upstream_mcp_manager = manager
    app.include_router(federation_router)
    principal = {
        "user": User(
            subject="tenant-a",
            username="admin",
            roles=["gateway-admin", "gateway-auditor"],
        )
    }

    async def current_user_override() -> User:
        return principal["user"]

    def db_override():
        yield db

    app.dependency_overrides[get_current_user] = current_user_override
    app.dependency_overrides[get_db] = db_override
    return TestClient(app), principal


def test_root_management_api_is_hash_only_versioned_and_tenant_scoped(db: Session) -> None:
    server = _server(db)
    manager = UpstreamMcpManager(
        public_base_url="https://gateway.example.test",
        gateway_roots_by_server={
            server.id: [{"uri": "file:///srv/project", "name": "Project"}]
        },
    )
    client, principal = _client(db, manager)

    openapi = client.app.openapi()
    schemas = openapi["components"]["schemas"]
    assert set(schemas["McpGatewayRootsSync"]["properties"]) == {
        "expected_server_version"
    }
    assert set(schemas["McpRootGrantReview"]["properties"]) == {
        "expected_version",
        "decision",
    }
    root_properties = set(schemas["McpRootGrantOut"]["properties"])
    assert "uri" not in root_properties
    assert "path" not in root_properties

    injected = client.post(
        f"/api/mcp/servers/{server.id}/roots/sync",
        json={
            "expected_server_version": server.version,
            "uri": "file:///attacker-controlled",
        },
    )
    assert injected.status_code == 422

    conflict = client.post(
        f"/api/mcp/servers/{server.id}/roots/sync",
        json={"expected_server_version": server.version + 1},
    )
    assert conflict.status_code == 409

    synced = client.post(
        f"/api/mcp/servers/{server.id}/roots/sync",
        json={"expected_server_version": server.version},
    )
    assert synced.status_code == 200, synced.text
    grants = synced.json()
    assert len(grants) == 1
    grant = grants[0]
    assert grant["status"] == "pending"
    assert grant["server_id"] == server.id
    assert grant["root_uri_hint"].startswith("gateway-root:")
    assert "file:///srv/project" not in synced.text

    listed = client.get(f"/api/mcp/root-grants?server_id={server.id}&status=pending")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [grant["id"]]

    approved = client.post(
        f"/api/mcp/root-grants/{grant['id']}/review",
        json={"expected_version": grant["version"], "decision": "approved"},
    )
    assert approved.status_code == 200, approved.text
    approved_grant = approved.json()
    assert approved_grant["status"] == "approved"
    assert approved_grant["version"] == grant["version"] + 1
    assert "file:///srv/project" not in approved.text

    principal["user"] = User(
        subject="tenant-b",
        username="other-admin",
        roles=["gateway-admin", "gateway-auditor"],
    )
    cross_tenant_list = client.get("/api/mcp/root-grants")
    assert cross_tenant_list.status_code == 200
    assert cross_tenant_list.json() == []
    cross_tenant_review = client.post(
        f"/api/mcp/root-grants/{grant['id']}/review",
        json={
            "expected_version": approved_grant["version"],
            "decision": "revoked",
        },
    )
    assert cross_tenant_review.status_code == 404

    principal["user"] = User(
        subject="tenant-a",
        username="admin",
        roles=["gateway-admin", "gateway-auditor"],
    )
    revoked = client.post(
        f"/api/mcp/root-grants/{grant['id']}/review",
        json={
            "expected_version": approved_grant["version"],
            "decision": "revoked",
        },
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert db.query(McpRootGrant).one().status == "revoked"


def test_gateway_root_sync_rejects_thin_client_server(db: Session) -> None:
    server = _server(db, origin="thin_client")
    manager = UpstreamMcpManager(public_base_url="https://gateway.example.test")
    client, _principal = _client(db, manager)
    response = client.post(
        f"/api/mcp/servers/{server.id}/roots/sync",
        json={"expected_server_version": server.version},
    )
    assert response.status_code == 422
    assert db.query(McpRootGrant).count() == 0
