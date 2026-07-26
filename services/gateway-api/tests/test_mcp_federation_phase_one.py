from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from jsonschema import (
    Draft202012Validator,
    ValidationError as JsonSchemaValidationError,
)
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from gateway_api.auth import get_current_user
from gateway_api.config import get_settings
from gateway_api.database import get_db
from gateway_api.dto import McpCallReadInput, McpServerCreate
from gateway_api.main import create_app
from gateway_api.mcp_federation import mcp_federation_service
from gateway_api.mcp_federation_policy import (
    McpActionClass,
    McpApprovalClass,
    McpExposureMode,
    McpPolicyViolation,
    McpReadOnlyStatus,
    McpTrustLevel,
    authorize_tool_revision,
    derive_risk_evidence,
    reject_secret_shaped_payload,
    validate_operator_classification,
)
from gateway_api.models import Base, McpToolRevision, User
from gateway_api.routers.mcp_federation import router as federation_router


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


def _server_data(name: str = "Build MCP") -> dict:
    return {
        "display_name": name,
        "origin": "gateway",
        "transport": "streamable_http",
        "endpoint_url": "https://mcp.example.test/mcp",
        "thin_client_id": None,
        "runtime_id": None,
        "credential_binding_id": None,
    }


def _record_revision(
    db: Session,
    *,
    server_id: str,
    input_schema: dict,
    generation: int,
):
    return mcp_federation_service.record_tool_revision(
        db,
        owner_subject="tenant-a",
        actor_subject="catalog-worker",
        server_id=server_id,
        upstream_name="get_build",
        input_schema=input_schema,
        output_schema={"type": "object"},
        title="Build",
        description="Read build metadata",
        annotations={"readOnlyHint": True},
        protocol_version="2025-11-25",
        catalog_generation=generation,
    )


def test_sqlite_metadata_contains_federation_tables(db: Session) -> None:
    tables = set(inspect(db.bind).get_table_names())
    assert {
        "mcp_credential_bindings",
        "mcp_servers",
        "mcp_tools",
        "mcp_tool_revisions",
        "mcp_tool_exposures",
        "mcp_federation_policies",
        "mcp_runtime_connections",
        "mcp_mutation_receipts",
        "mcp_invocations",
    }.issubset(tables)


def test_secret_and_identity_fields_fail_closed() -> None:
    with pytest.raises(McpPolicyViolation, match="Secret-shaped"):
        reject_secret_shaped_payload(
            {"type": "object", "properties": {"api_token": {"type": "string"}}}
        )
    with pytest.raises(ValidationError, match="Caller-controlled"):
        McpCallReadInput(
            tool_ref="server/tool/revision",
            schema_hash="a" * 64,
            arguments={"tenant_id": "tenant-b"},
        )
    with pytest.raises(ValidationError, match="endpoint_url"):
        McpServerCreate(
            display_name="Remote MCP",
            origin="gateway",
            transport="streamable_http",
        )
    with pytest.raises(ValidationError):
        McpServerCreate(
            display_name="Remote MCP",
            origin="gateway",
            transport="streamable_http",
            endpoint_url="https://mcp.example.test/mcp",
            password="forbidden",
        )


def test_upstream_annotations_are_advisory_and_read_requires_verification() -> None:
    evidence = derive_risk_evidence(
        tool_name="get_build",
        input_schema={"type": "object", "properties": {}},
        upstream_annotations={"readOnlyHint": True},
    )
    assert evidence == {
        "heuristic_action_class": "unknown",
        "upstream_read_only_hint": True,
        "upstream_destructive_hint": None,
        "authoritative": False,
    }
    with pytest.raises(McpPolicyViolation, match="independently verified"):
        validate_operator_classification(
            action_class=McpActionClass.READ,
            read_only_status=McpReadOnlyStatus.UNVERIFIED,
        )
    denied = authorize_tool_revision(
        actor_roles={"gateway-operator"},
        actor_scopes={"mcp:read"},
        trust_level=McpTrustLevel.APPROVED,
        exposure_mode=McpExposureMode.CATALOG_ONLY,
        exposure_enabled=True,
        action_class=McpActionClass.READ,
        read_only_status=McpReadOnlyStatus.UNVERIFIED,
        required_role="gateway-operator",
        required_scope="mcp:read",
        allowed_action_classes={"read"},
    )
    assert denied.allowed is False
    allowed = authorize_tool_revision(
        actor_roles={"gateway-operator"},
        actor_scopes={"mcp:read"},
        trust_level=McpTrustLevel.APPROVED,
        exposure_mode=McpExposureMode.CATALOG_ONLY,
        exposure_enabled=True,
        action_class=McpActionClass.READ,
        read_only_status=McpReadOnlyStatus.VERIFIED,
        required_role="gateway-operator",
        required_scope="mcp:read",
        allowed_action_classes={"read"},
    )
    assert allowed.allowed is True
    assert allowed.approval_class is McpApprovalClass.NONE


def test_server_idempotency_and_tenant_isolation(db: Session) -> None:
    created = mcp_federation_service.create_server(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        idempotency_key="server-create-1",
        data=_server_data(),
    )
    replayed = mcp_federation_service.create_server(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        idempotency_key="server-create-1",
        data=_server_data(),
    )
    assert replayed.id == created.id
    assert replayed.display_name == "Build MCP"
    with pytest.raises(HTTPException) as mismatched_replay:
        mcp_federation_service.create_server(
            db,
            owner_subject="tenant-a",
            actor_subject="tenant-a",
            idempotency_key="server-create-1",
            data=_server_data("Different Request"),
        )
    assert mismatched_replay.value.status_code == 409
    with pytest.raises(HTTPException) as missing:
        mcp_federation_service.get_server(
            db, owner_subject="tenant-b", server_id=created.id
        )
    assert missing.value.status_code == 404
    with pytest.raises(HTTPException) as conflict:
        mcp_federation_service.update_server(
            db,
            owner_subject="tenant-a",
            actor_subject="tenant-a",
            server_id=created.id,
            idempotency_key="server-update-conflict",
            expected_version=created.version + 1,
            data={"display_name": "Conflict"},
        )
    assert conflict.value.status_code == 409


def test_rest_control_plane_requires_idempotency_and_versions(db: Session) -> None:
    app = FastAPI()
    app.include_router(federation_router)
    principal = User(
        subject="tenant-a",
        username="admin",
        roles=["gateway-admin", "gateway-auditor"],
    )

    async def current_user_override() -> User:
        return principal

    def db_override():
        yield db

    app.dependency_overrides[get_current_user] = current_user_override
    app.dependency_overrides[get_db] = db_override
    client = TestClient(app)
    payload = {
        "display_name": "REST MCP",
        "origin": "gateway",
        "transport": "streamable_http",
        "endpoint_url": "https://rest-mcp.example.test/mcp",
    }
    missing_key = client.post("/api/mcp/servers", json=payload)
    assert missing_key.status_code == 422
    created = client.post(
        "/api/mcp/servers",
        json=payload,
        headers={"Idempotency-Key": "rest-server-create-1"},
    )
    assert created.status_code == 201
    server = created.json()
    replay = client.post(
        "/api/mcp/servers",
        json=payload,
        headers={"Idempotency-Key": "rest-server-create-1"},
    )
    assert replay.status_code == 201
    assert replay.json()["id"] == server["id"]

    tool, _, _ = _record_revision(
        db,
        server_id=server["id"],
        input_schema={"type": "object", "properties": {}},
        generation=1,
    )
    missing_exposure = client.get(f"/api/mcp/tools/{tool.id}/exposure")
    assert missing_exposure.status_code == 200
    assert missing_exposure.json() is None

    mismatched_replay = client.post(
        "/api/mcp/servers",
        json={**payload, "display_name": "Different Request"},
        headers={"Idempotency-Key": "rest-server-create-1"},
    )
    assert mismatched_replay.status_code == 409

    patch_payload = {
        "expected_version": server["version"],
        "display_name": "REST MCP Updated",
    }
    missing_patch_key = client.patch(
        f"/api/mcp/servers/{server['id']}", json=patch_payload
    )
    assert missing_patch_key.status_code == 422
    updated = client.patch(
        f"/api/mcp/servers/{server['id']}",
        json=patch_payload,
        headers={"Idempotency-Key": "rest-server-update-1"},
    )
    assert updated.status_code == 200
    updated_server = updated.json()
    assert updated_server["version"] == server["version"] + 1
    patch_replay = client.patch(
        f"/api/mcp/servers/{server['id']}",
        json=patch_payload,
        headers={"Idempotency-Key": "rest-server-update-1"},
    )
    assert patch_replay.status_code == 200
    assert patch_replay.json()["version"] == updated_server["version"]

    missing_delete_headers = client.delete(f"/api/mcp/servers/{server['id']}")
    assert missing_delete_headers.status_code == 422
    missing_delete_key = client.delete(
        f"/api/mcp/servers/{server['id']}",
        headers={"If-Match": str(updated_server["version"])},
    )
    assert missing_delete_key.status_code == 422
    delete_headers = {
        "If-Match": str(updated_server["version"]),
        "Idempotency-Key": "rest-server-disable-1",
    }
    disabled = client.delete(f"/api/mcp/servers/{server['id']}", headers=delete_headers)
    assert disabled.status_code == 200
    disabled_server = disabled.json()
    assert disabled_server["status"] == "disabled"
    disable_replay = client.delete(
        f"/api/mcp/servers/{server['id']}", headers=delete_headers
    )
    assert disable_replay.status_code == 200
    assert disable_replay.json()["version"] == disabled_server["version"]


def test_immutable_tool_revision_lifecycle_and_exposure_policy(db: Session) -> None:
    server = mcp_federation_service.create_server(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        idempotency_key="server-create-2",
        data=_server_data(),
    )
    tool, revision_one, created = _record_revision(
        db,
        server_id=server.id,
        input_schema={
            "type": "object",
            "properties": {"build_id": {"type": "integer"}},
        },
        generation=1,
    )
    assert created is True
    assert revision_one.action_class == "unknown"
    _, replayed, created = _record_revision(
        db,
        server_id=server.id,
        input_schema={
            "type": "object",
            "properties": {"build_id": {"type": "integer"}},
        },
        generation=1,
    )
    assert created is False
    assert replayed.id == revision_one.id
    _, revision_two, created = _record_revision(
        db,
        server_id=server.id,
        input_schema={
            "type": "object",
            "properties": {
                "build_id": {"type": "integer"},
                "detail": {"type": "boolean"},
            },
        },
        generation=2,
    )
    assert created is True
    assert revision_two.tool_id == tool.id
    assert revision_two.id != revision_one.id
    db.refresh(revision_one)
    assert revision_one.superseded_by_revision_id == revision_two.id
    assert db.query(McpToolRevision).filter_by(tool_id=tool.id).count() == 2

    with pytest.raises(HTTPException) as unknown_risk:
        mcp_federation_service.upsert_exposure(
            db,
            owner_subject="tenant-a",
            actor_subject="admin",
            tool_id=tool.id,
            idempotency_key="unknown-risk-exposure",
            expected_version=0,
            data={
                "revision_id": revision_two.id,
                "mode": "catalog_only",
                "enabled": True,
                "projected_name": None,
                "required_role": None,
                "required_scope": None,
                "approval_class": "none",
                "projection_generation": 0,
            },
        )
    assert unknown_risk.value.status_code == 409

    classified = mcp_federation_service.classify_revision(
        db,
        owner_subject="tenant-a",
        actor_subject="admin",
        revision_id=revision_two.id,
        idempotency_key="revision-classify-1",
        expected_version=revision_two.version,
        action_class="read",
        read_only_status="verified",
    )
    assert classified.schema_hash == revision_two.schema_hash
    assert classified.input_schema == revision_two.input_schema

    policy = mcp_federation_service.upsert_policy(
        db,
        owner_subject="tenant-a",
        actor_subject="admin",
        server_id=server.id,
        idempotency_key="policy-create-1",
        expected_version=0,
        data={
            "trust_level": "approved",
            "allowed_action_classes": ["read"],
            "required_roles": [],
            "required_scopes": [],
            "approval_mapping": {"read": "none"},
            "tool_allowlist": [],
            "tool_denylist": [],
            "status": "active",
        },
    )
    assert policy.generation == 1
    policy_replay = mcp_federation_service.upsert_policy(
        db,
        owner_subject="tenant-a",
        actor_subject="admin",
        server_id=server.id,
        idempotency_key="policy-create-1",
        expected_version=0,
        data={
            "trust_level": "approved",
            "allowed_action_classes": ["read"],
            "required_roles": [],
            "required_scopes": [],
            "approval_mapping": {"read": "none"},
            "tool_allowlist": [],
            "tool_denylist": [],
            "status": "active",
        },
    )
    assert policy_replay.id == policy.id
    assert policy_replay.generation == 1
    classification_replay = mcp_federation_service.classify_revision(
        db,
        owner_subject="tenant-a",
        actor_subject="admin",
        revision_id=revision_two.id,
        idempotency_key="revision-classify-1",
        expected_version=revision_two.version - 1,
        action_class="read",
        read_only_status="verified",
    )
    assert classification_replay.version == classified.version
    exposure = mcp_federation_service.upsert_exposure(
        db,
        owner_subject="tenant-a",
        actor_subject="admin",
        tool_id=tool.id,
        idempotency_key="native-exposure-1",
        expected_version=0,
        data={
            "revision_id": revision_two.id,
            "mode": "native_projected",
            "enabled": True,
            "projected_name": "build_get",
            "required_role": "gateway-operator",
            "required_scope": "mcp:read",
            "approval_class": "none",
            "projection_generation": 1,
        },
    )
    assert exposure.enabled is True
    assert exposure.policy_generation == policy.generation


def test_phase_one_machine_readable_contracts() -> None:
    root = Path(__file__).resolve().parents[3]
    broker_path = root / "schemas" / "gateway.mcp.broker_tools.v1.schema.json"
    broker = json.loads(broker_path.read_text())
    call_read_schema = {
        **broker["$defs"]["mcp_call_read"],
        "$defs": broker["$defs"],
    }
    validator = Draft202012Validator(call_read_schema)
    validator.validate(
        {
            "tool_ref": "server/tool/revision",
            "schema_hash": "a" * 64,
            "arguments": {"build_id": 42},
        }
    )
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(
            {
                "tool_ref": "server/tool/revision",
                "schema_hash": "a" * 64,
                "arguments": {"credential_id": "caller-controlled"},
            }
        )

    openapi = yaml.safe_load(
        (root / "openapi" / "mcp-federation.openapi.yaml").read_text()
    )
    dynamic_paths = {
        path for path in create_app().openapi()["paths"] if path.startswith("/api/mcp/")
    }
    assert set(openapi["paths"]) == dynamic_paths
    assert len(dynamic_paths) == 28

    asyncapi = yaml.safe_load(
        (root / "asyncapi" / "gateway-events.asyncapi.yaml").read_text()
    )
    mcp_channels = {
        name: channel
        for name, channel in asyncapi["channels"].items()
        if name.startswith("gateway.mcp.")
    }
    assert len(mcp_channels) == 25
    for event_type, channel in mcp_channels.items():
        message_ref = channel["publish"]["message"]["$ref"]
        message = asyncapi["components"]["messages"][message_ref.rsplit("/", 1)[-1]]
        assert message["name"] == event_type
        schema_path = (root / "asyncapi" / message["payload"]["$ref"]).resolve()
        schema = json.loads(schema_path.read_text())
        Draft202012Validator.check_schema(schema)
        if ".invocation." in event_type:
            serialized = json.dumps(schema).lower()
            assert "arguments" not in serialized
            assert "result" not in serialized

    migration = (
        root / "database" / "migrations" / "002_mcp_federation_control_plane.sql"
    ).read_text()
    assert "gateway_mcp_tool_revision_guard" in migration
    assert "mcp_tool_revisions are append-only" in migration
    assert "DROP TABLE" not in migration.upper()
