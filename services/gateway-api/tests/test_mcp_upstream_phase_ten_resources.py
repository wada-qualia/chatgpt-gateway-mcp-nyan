from __future__ import annotations

import asyncio
import contextlib
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from gateway_api.database import Base
from gateway_api.mcp_resource_federation import (
    public_resource_uri,
    reconcile_resource_catalog,
)
from gateway_api.mcp_upstream import (
    UpstreamMcpError,
    UpstreamMcpManager,
    _list_session_resource_catalog,
)
from gateway_api.models import (
    McpCapabilityEntity,
    McpCapabilityEntityRevision,
    McpServer,
)
from mcp.shared.exceptions import MCPError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

OWNER = "phase10-upstream-owner"
SERVER_ID = "21111111-1111-4111-8111-111111111111"
PROTOCOL = "2025-11-25"
RESOURCE_URI = "https://provider.example/resources/42"


class _Dumpable:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return dict(self.payload)


class _Page:
    def __init__(
        self,
        *,
        resources: list[Any] | None = None,
        resource_templates: list[Any] | None = None,
        next_cursor: str | None = None,
    ) -> None:
        self.resources = resources if resources is not None else []
        self.resource_templates = (
            resource_templates if resource_templates is not None else []
        )
        self.next_cursor = next_cursor


class _CatalogSession:
    def __init__(self) -> None:
        self.resource_cursors: list[str | None] = []

    async def list_resources(self, params: Any = None) -> _Page:
        cursor = getattr(params, "cursor", None) if params is not None else None
        self.resource_cursors.append(cursor)
        if cursor is None:
            return _Page(
                resources=[
                    _Dumpable(
                        {
                            "uri": "https://provider.example/resources/one",
                            "name": "one",
                            "mimeType": "text/plain",
                        }
                    )
                ],
                next_cursor="page-2",
            )
        assert cursor == "page-2"
        return _Page(
            resources=[
                _Dumpable(
                    {
                        "uri": "https://provider.example/resources/two",
                        "name": "two",
                        "mimeType": "text/plain",
                    }
                )
            ]
        )

    async def list_resource_templates(self, params: Any = None) -> _Page:
        del params
        raise MCPError(-32601, "Method not found")


class _ReadSession:
    def __init__(self, exact_uri: str) -> None:
        self.exact_uri = exact_uri
        self.read_uris: list[str] = []

    async def list_resources(self, params: Any = None) -> _Page:
        del params
        return _Page(
            resources=[
                _Dumpable(
                    {
                        "uri": self.exact_uri,
                        "name": "reviewed resource",
                        "mimeType": "text/plain",
                    }
                )
            ]
        )

    async def list_resource_templates(self, params: Any = None) -> _Page:
        del params
        return _Page()

    async def read_resource(self, uri: str) -> _Dumpable:
        self.read_uris.append(str(uri))
        return _Dumpable(
            {
                "contents": [
                    {
                        "uri": str(uri),
                        "mimeType": "text/plain",
                        "text": "remote evidence",
                    }
                ]
            }
        )


def _db() -> tuple[object, Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine, Session(engine, expire_on_commit=False)


def _server(db: Session) -> McpServer:
    server = McpServer(
        id=SERVER_ID,
        owner_subject=OWNER,
        origin="gateway",
        display_name="Remote resources",
        normalized_slug="remote-resources",
        transport="streamable_http",
        status="online",
        trust_level="restricted",
        capabilities={},
        catalog_generation=0,
        policy_generation=1,
        version=1,
    )
    db.add(server)
    db.flush([server])
    return server


def _catalog(db: Session) -> tuple[McpCapabilityEntity, McpCapabilityEntityRevision]:
    reconcile_resource_catalog(
        db,
        owner_subject=OWNER,
        server_id=SERVER_ID,
        protocol_version=PROTOCOL,
        catalog_generation=1,
        resources=[
            {
                "uri": RESOURCE_URI,
                "name": "reviewed resource",
                "mimeType": "text/plain",
            }
        ],
        resource_templates=[],
    )
    entity = (
        db.query(McpCapabilityEntity)
        .filter_by(
            owner_subject=OWNER,
            server_id=SERVER_ID,
            entity_kind="resource",
        )
        .one()
    )
    revision = db.query(McpCapabilityEntityRevision).filter_by(
        id=entity.current_revision_id
    ).one()
    return entity, revision


def test_remote_resource_catalog_paginates_and_legacy_method_not_found_is_empty() -> None:
    session = _CatalogSession()
    resources, templates = asyncio.run(_list_session_resource_catalog(session))

    assert [item["name"] for item in resources] == ["one", "two"]
    assert templates == []
    assert session.resource_cursors == [None, "page-2"]


def test_remote_read_re_resolves_exact_catalog_uri_not_public_client_uri(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _engine, db = _db()
    try:
        server = _server(db)
        entity, revision = _catalog(db)
        session = _ReadSession(RESOURCE_URI)
        manager = UpstreamMcpManager(public_base_url="https://gateway.example.test")

        @contextlib.asynccontextmanager
        async def fake_session(_db: Session, selected: McpServer):
            assert selected.id == server.id
            yield session, SimpleNamespace(protocolVersion=PROTOCOL), None

        monkeypatch.setattr(manager, "_session", fake_session)
        public_uri = "https://client-controlled.invalid/not-an-upstream-target"
        result = asyncio.run(
            manager.read_exact_resource(
                db,
                owner_subject=OWNER,
                server=server,
                entity=entity,
                revision=revision,
                arguments={},
                public_uri=public_uri,
            )
        )

        assert session.read_uris == [RESOURCE_URI]
        assert result["contents"][0]["uri"] == public_uri
        assert result["contents"][0]["text"] == "remote evidence"
        provenance = result["_meta"]["gateway"]["resourceProvenance"]
        assert provenance["entity_id"] == entity.id
        assert provenance["catalog_revision_id"] == revision.id
        assert "client-controlled.invalid" not in str(provenance)
    finally:
        db.close()


def test_stale_remote_resource_revision_fails_before_opening_upstream_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _engine, db = _db()
    try:
        server = _server(db)
        entity, revision = _catalog(db)
        entity.current_revision_id = str(uuid.uuid4())
        db.flush([entity])
        manager = UpstreamMcpManager(public_base_url="https://gateway.example.test")
        opened = False

        @contextlib.asynccontextmanager
        async def forbidden_session(_db: Session, _selected: McpServer):
            nonlocal opened
            opened = True
            yield _ReadSession(RESOURCE_URI), SimpleNamespace(protocolVersion=PROTOCOL), None

        monkeypatch.setattr(manager, "_session", forbidden_session)
        with pytest.raises(UpstreamMcpError) as exc_info:
            asyncio.run(
                manager.read_exact_resource(
                    db,
                    owner_subject=OWNER,
                    server=server,
                    entity=entity,
                    revision=revision,
                    arguments={},
                    public_uri=public_resource_uri(entity.id, revision.id),
                )
            )
        assert exc_info.value.code == "MCP_RESOURCE_BINDING_STALE"
        assert opened is False
    finally:
        db.close()
