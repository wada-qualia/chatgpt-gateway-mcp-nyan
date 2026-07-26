from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path
from types import MethodType, SimpleNamespace
from urllib.parse import parse_qs, urlparse

from fastapi import HTTPException
import httpx
from pydantic import SecretStr
import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from gateway_api.config import Settings, get_settings
from gateway_api.database import Base
from gateway_api.mcp_federation import mcp_federation_service
from gateway_api.mcp_oauth_discovery import (
    discover_oauth_metadata,
    oidc_discovery_urls,
    well_known_url,
)
from gateway_api.mcp_upstream import (
    UpstreamMcpError,
    UpstreamMcpManager,
    _bearer_challenge_scopes,
)
from gateway_api.mcp_upstream_credentials import start_oauth_authorization
from gateway_api.mcp_upstream_dto import McpOAuthAuthorizationStart
from gateway_api.models import (
    McpCredentialBinding,
    McpOAuthAuthorizationState,
    McpOAuthDiscoverySnapshot,
    utcnow,
)
from gateway_api.routers.oauth import oauth_client_metadata

ROOT = Path(__file__).resolve().parents[3]
RESOURCE = "https://mcp.example.test/mcp"
RESOURCE_METADATA = (
    "https://mcp.example.test/.well-known/oauth-protected-resource/mcp"
)
ISSUER = "https://auth.example.test/tenant"
AS_METADATA = (
    "https://auth.example.test/.well-known/oauth-authorization-server/tenant"
)


@pytest.fixture
def db(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GATEWAY_OUTBOX_ENABLED", "false")
    monkeypatch.setenv(
        "GATEWAY_SECRET_KEY",
        "phase-eight-oauth-discovery-test-key-0000000000000000",
    )
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


def _server(db: Session, *, suffix: str = "primary"):
    return mcp_federation_service.create_server(
        db,
        owner_subject="tenant-a",
        actor_subject="operator-a",
        idempotency_key=f"oauth-discovery-server-{suffix}",
        data={
            "display_name": f"OAuth discovery {suffix}",
            "origin": "gateway",
            "transport": "streamable_http",
            "endpoint_url": RESOURCE,
            "thin_client_id": None,
            "runtime_id": None,
            "credential_binding_id": None,
        },
    )


def _manager() -> UpstreamMcpManager:
    manager = UpstreamMcpManager(public_base_url="https://gateway.example.test")

    async def validate_endpoint(
        self: UpstreamMcpManager,
        endpoint: str,
        *,
        purpose: str = "mcp",
    ) -> SimpleNamespace:
        del self, purpose
        return SimpleNamespace(endpoint=endpoint)

    manager.validate_endpoint = MethodType(validate_endpoint, manager)
    return manager


def _metadata_transport(
    *,
    resource: str = RESOURCE,
    issuers: list[str] | None = None,
    cache_control: str = "max-age=300",
    metadata_document_supported: bool = True,
):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert "authorization" not in request.headers
        if str(request.url) == RESOURCE_METADATA:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json", "Cache-Control": cache_control},
                json={
                    "resource": resource,
                    "authorization_servers": issuers or [ISSUER],
                    "scopes_supported": ["mcp:read", "mcp:call"],
                    "bearer_methods_supported": ["header"],
                    "client_secret": "must-not-persist",
                    "access_token": "must-not-persist",
                },
            )
        if str(request.url) == AS_METADATA:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json", "Cache-Control": cache_control},
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "registration_endpoint": f"{ISSUER}/register",
                    "scopes_supported": ["mcp:read", "mcp:call", "openid"],
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code"],
                    "code_challenge_methods_supported": ["S256"],
                    "client_id_metadata_document_supported": (
                        metadata_document_supported
                    ),
                    "client_secret": "must-not-persist",
                    "refresh_token": "must-not-persist",
                },
            )
        return httpx.Response(
            404,
            headers={"Content-Type": "application/json", "Cache-Control": cache_control},
            json={"error": "not_found"},
        )

    return httpx.MockTransport(handler), requests


def test_well_known_url_construction_is_path_aware() -> None:
    assert well_known_url(RESOURCE, "oauth-protected-resource") == RESOURCE_METADATA
    assert well_known_url(ISSUER, "oauth-authorization-server") == AS_METADATA
    assert oidc_discovery_urls(ISSUER) == (
        "https://auth.example.test/tenant/.well-known/openid-configuration",
        "https://auth.example.test/.well-known/openid-configuration/tenant",
    )


def test_discovery_is_sanitized_idempotent_and_authorization_is_fenced(
    db: Session,
) -> None:
    async def scenario() -> None:
        server = _server(db)
        manager = _manager()
        transport, requests = _metadata_transport()
        async with httpx.AsyncClient(transport=transport) as client:
            first = await discover_oauth_metadata(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                expected_version=server.version,
                requested_scopes=["mcp:read"],
                client=client,
            )
            second = await discover_oauth_metadata(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                expected_version=server.version,
                requested_scopes=["mcp:read"],
                client=client,
            )
        assert first.id == second.id
        assert db.query(McpOAuthDiscoverySnapshot).count() == 1
        assert first.resource == RESOURCE
        assert first.authorization_server == ISSUER
        assert first.discovery_mechanism == "rfc8414"
        assert first.proposed_scopes == ["mcp:read"]
        serialized = str(first.protected_resource_metadata) + str(
            first.authorization_server_metadata
        )
        for forbidden in (
            "must-not-persist",
            "client_secret",
            "access_token",
            "refresh_token",
        ):
            assert forbidden not in serialized
        assert len(requests) == 2
        assert first.expires_at > first.created_at

        with pytest.raises(HTTPException) as scope_error:
            await start_oauth_authorization(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                idempotency_key="oauth-discovery-scope-escalation",
                payload=McpOAuthAuthorizationStart(
                    expected_version=server.version,
                    discovery_snapshot_id=first.id,
                    client_id="gateway-client",
                    redirect_uri="https://gateway.example.test/mcp-connections",
                    scopes=["mcp:admin"],
                ),
            )
        assert scope_error.value.status_code == 422

        started = await start_oauth_authorization(
            db,
            manager=manager,
            owner_subject="tenant-a",
            actor_subject="operator-a",
            server_id=server.id,
            idempotency_key="oauth-discovery-start",
            payload=McpOAuthAuthorizationStart(
                expected_version=server.version,
                discovery_snapshot_id=first.id,
                client_id="gateway-client",
                client_secret=SecretStr("backend-only-client-secret"),
                redirect_uri="https://gateway.example.test/mcp-connections",
                scopes=[],
            ),
        )
        assert "backend-only-client-secret" not in str(started)
        flow = db.query(McpOAuthAuthorizationState).one()
        binding = db.get(McpCredentialBinding, flow.binding_id)
        assert binding is not None
        assert flow.authorization_endpoint == f"{ISSUER}/authorize"
        assert flow.token_endpoint == f"{ISSUER}/token"
        assert flow.audience == RESOURCE
        assert flow.scopes == ["mcp:read"]
        assert binding.audience == RESOURCE
        assert binding.scopes == ["mcp:read"]
        assert binding.meta["backend_reference"] is True
        assert binding.meta["discovery_snapshot_id"] == first.id
        assert binding.meta["client_registration_mode"] == "static_preregistered"

    asyncio.run(scenario())


def test_discovery_rejects_resource_and_issuer_ambiguity(db: Session) -> None:
    async def scenario() -> None:
        manager = _manager()
        server = _server(db, suffix="fail-closed")
        mismatch_transport, _ = _metadata_transport(
            resource="https://mcp.example.test/other"
        )
        async with httpx.AsyncClient(transport=mismatch_transport) as client:
            with pytest.raises(UpstreamMcpError) as mismatch:
                await discover_oauth_metadata(
                    db,
                    manager=manager,
                    owner_subject="tenant-a",
                    actor_subject="operator-a",
                    server_id=server.id,
                    expected_version=server.version,
                    requested_scopes=[],
                    client=client,
                )
        assert mismatch.value.code == "MCP_AUTH_DISCOVERY_AUDIENCE_MISMATCH"

        ambiguous_transport, _ = _metadata_transport(
            issuers=[ISSUER, "https://auth-two.example.test"]
        )
        async with httpx.AsyncClient(transport=ambiguous_transport) as client:
            with pytest.raises(UpstreamMcpError) as ambiguous:
                await discover_oauth_metadata(
                    db,
                    manager=manager,
                    owner_subject="tenant-a",
                    actor_subject="operator-a",
                    server_id=server.id,
                    expected_version=server.version,
                    requested_scopes=[],
                    client=client,
                )
        assert ambiguous.value.code == "MCP_AUTH_DISCOVERY_SELECTION_REQUIRED"
        assert db.query(McpOAuthDiscoverySnapshot).count() == 0

    asyncio.run(scenario())


def test_expired_metadata_keeps_issuer_pin_and_rejects_issuer_swap(
    db: Session,
) -> None:
    async def scenario() -> None:
        manager = _manager()
        server = _server(db, suffix="issuer-pin")
        first_transport, _ = _metadata_transport(cache_control="no-store")
        async with httpx.AsyncClient(transport=first_transport) as client:
            first = await discover_oauth_metadata(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                expected_version=server.version,
                requested_scopes=[],
                client=client,
            )
        assert first.expires_at <= first.created_at + timedelta(seconds=1)

        multi_transport, _ = _metadata_transport(
            issuers=["https://auth-two.example.test", ISSUER],
            cache_control="no-store",
        )
        async with httpx.AsyncClient(transport=multi_transport) as client:
            refreshed = await discover_oauth_metadata(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                expected_version=server.version,
                requested_scopes=[],
                client=client,
            )
        assert refreshed.id != first.id
        assert refreshed.authorization_server == ISSUER

        swapped_transport, _ = _metadata_transport(
            issuers=["https://auth-two.example.test"],
            cache_control="no-store",
        )
        async with httpx.AsyncClient(transport=swapped_transport) as client:
            with pytest.raises(UpstreamMcpError) as changed:
                await discover_oauth_metadata(
                    db,
                    manager=manager,
                    owner_subject="tenant-a",
                    actor_subject="operator-a",
                    server_id=server.id,
                    expected_version=server.version,
                    requested_scopes=[],
                    client=client,
                )
        assert changed.value.code == "MCP_AUTH_DISCOVERY_ISSUER_CHANGED"

    asyncio.run(scenario())


def test_client_id_metadata_document_mode_and_public_document(db: Session) -> None:
    async def scenario() -> None:
        manager = _manager()
        server = _server(db, suffix="client-metadata")
        transport, _ = _metadata_transport()
        async with httpx.AsyncClient(transport=transport) as client:
            snapshot = await discover_oauth_metadata(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                expected_version=server.version,
                requested_scopes=["mcp:read"],
                client=client,
            )
        metadata = oauth_client_metadata(
            "https://gateway.example.test",
            Settings(public_base_url="https://gateway.example.test"),
        )
        assert metadata["client_id"] == (
            "https://gateway.example.test/oauth/client-metadata.json"
        )
        assert metadata["redirect_uris"] == [
            "https://gateway.example.test/mcp-connections"
        ]
        started = await start_oauth_authorization(
            db,
            manager=manager,
            owner_subject="tenant-a",
            actor_subject="operator-a",
            server_id=server.id,
            idempotency_key="oauth-client-metadata-start",
            payload=McpOAuthAuthorizationStart(
                expected_version=server.version,
                discovery_snapshot_id=snapshot.id,
                client_id=metadata["client_id"],
                redirect_uri=metadata["redirect_uris"][0],
                scopes=[],
            ),
        )
        authorization_query = parse_qs(
            urlparse(started["authorization_url"]).query
        )
        assert authorization_query["client_id"] == [metadata["client_id"]]
        binding = db.query(McpCredentialBinding).one()
        assert binding.meta["client_registration_mode"] == (
            "client_id_metadata_document"
        )

        unsupported_server = _server(db, suffix="client-metadata-unsupported")
        unsupported_transport, _ = _metadata_transport(
            metadata_document_supported=False
        )
        async with httpx.AsyncClient(transport=unsupported_transport) as client:
            unsupported_snapshot = await discover_oauth_metadata(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=unsupported_server.id,
                expected_version=unsupported_server.version,
                requested_scopes=[],
                client=client,
            )
        with pytest.raises(HTTPException) as unsupported:
            await start_oauth_authorization(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=unsupported_server.id,
                idempotency_key="oauth-client-metadata-unsupported",
                payload=McpOAuthAuthorizationStart(
                    expected_version=unsupported_server.version,
                    discovery_snapshot_id=unsupported_snapshot.id,
                    client_id=metadata["client_id"],
                    redirect_uri=metadata["redirect_uris"][0],
                    scopes=[],
                ),
            )
        assert unsupported.value.status_code == 422

    asyncio.run(scenario())


def test_incremental_scope_challenge_is_bounded_and_requires_consent(
    db: Session,
) -> None:
    assert _bearer_challenge_scopes(
        'Bearer error="insufficient_scope", scope="mcp:read mcp:write"'
    ) == ["mcp:read", "mcp:write"]
    assert _bearer_challenge_scopes("Basic realm=example") == []
    assert _bearer_challenge_scopes(r"Bearer scope=bad\scope") == []
    assert _bearer_challenge_scopes("Bearer " + "x" * 5000) == []

    server = _server(db, suffix="scope-challenge")
    binding = McpCredentialBinding(
        id="44444444-4444-4444-8444-444444444444",
        owner_subject="tenant-a",
        binding_type="oauth",
        provider=None,
        secret_blob_id=None,
        audience=RESOURCE,
        scopes=["mcp:read"],
        status="active",
        version=1,
        meta={"mode": "oauth", "backend_reference": True},
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(binding)
    db.flush()
    server.credential_binding_id = binding.id
    db.commit()
    response = httpx.Response(
        403,
        headers={
            "WWW-Authenticate": (
                'Bearer error="insufficient_scope", '
                'scope="mcp:read mcp:write"'
            )
        },
    )
    error = UpstreamMcpManager._scope_upgrade_error(db, server, response)
    assert error is not None
    assert error.code == "MCP_AUTH_SCOPE_UPGRADE_REQUIRED"
    assert error.as_detail()["metadata"] == {
        "required_scopes": ["mcp:write"],
        "resource": RESOURCE,
    }
    assert "authorization" not in str(error.as_detail()).lower()
    db.refresh(binding)
    db.refresh(server)
    assert binding.status == "auth_required"
    assert binding.scopes == ["mcp:read"]
    assert server.status == "auth_required"


def test_expired_discovery_snapshot_cannot_start_authorization(
    db: Session,
) -> None:
    async def scenario() -> None:
        manager = _manager()
        server = _server(db, suffix="expired-start")
        transport, _ = _metadata_transport(cache_control="no-store")
        async with httpx.AsyncClient(transport=transport) as client:
            snapshot = await discover_oauth_metadata(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                expected_version=server.version,
                requested_scopes=["mcp:read"],
                client=client,
            )
        assert snapshot.expires_at <= snapshot.created_at + timedelta(seconds=1)
        with pytest.raises(HTTPException) as expired:
            await start_oauth_authorization(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                idempotency_key="oauth-expired-discovery-start",
                payload=McpOAuthAuthorizationStart(
                    expected_version=server.version,
                    discovery_snapshot_id=snapshot.id,
                    client_id="gateway-client",
                    redirect_uri="https://gateway.example.test/mcp-connections",
                    scopes=[],
                ),
            )
        assert expired.value.status_code == 409
        assert "rediscovery required" in str(expired.value.detail)
        assert db.query(McpOAuthAuthorizationState).count() == 0
        assert db.query(McpCredentialBinding).count() == 0

    asyncio.run(scenario())


def test_oauth_discovery_migration_contract() -> None:
    table = Base.metadata.tables["mcp_oauth_discovery_snapshots"]
    assert {
        "id",
        "owner_subject",
        "server_id",
        "resource",
        "authorization_server",
        "metadata_hash",
        "expires_at",
        "created_at",
    } <= set(table.columns.keys())

    migration = (
        ROOT / "database/alembic/versions/20260726_0007_mcp_oauth_discovery.py"
    ).read_text(encoding="utf-8")
    sql = (ROOT / "database/migrations/008_mcp_oauth_discovery.sql").read_text(
        encoding="utf-8"
    )
    baseline = (ROOT / "database/alembic/postgresql_baseline.sql").read_text(
        encoding="utf-8"
    )
    assert 'revision = "20260726_0007"' in migration
    assert 'down_revision = "20260726_0006"' in migration
    assert "partial MCP OAuth discovery schema" in migration
    assert "OAuth discovery snapshot downgrade is not supported" in migration
    assert baseline.count("CREATE TABLE mcp_oauth_discovery_snapshots") == 1
    assert "trg_mcp_oauth_discovery_snapshot_append_only" in sql

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    columns = {
        column["name"]
        for column in inspect(engine).get_columns("mcp_oauth_discovery_snapshots")
    }
    assert columns == set(table.columns.keys())
