from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session
import yaml

from gateway_api.database import Base
from gateway_api.mcp_capability_control_plane import (
    McpCapabilitySnapshotConflict,
    capability_snapshot_hash,
    record_capability_snapshot,
)
from gateway_api.models import McpRuntimeConnection, McpServer

ROOT = Path(__file__).resolve().parents[3]
CONTRACT_ROOT = ROOT / "contracts" / "mcp-federation" / "v1"
CAPABILITY_TABLES = {
    "mcp_capability_snapshots",
    "mcp_capability_entities",
    "mcp_capability_entity_revisions",
    "mcp_capability_subscriptions",
    "mcp_root_grants",
    "mcp_interaction_consents",
    "mcp_federated_tasks",
    "mcp_capability_events",
}


def _load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_phase_eight_capability_tables_and_contracts() -> None:
    assert CAPABILITY_TABLES <= set(Base.metadata.tables)
    for table_name in CAPABILITY_TABLES:
        columns = set(Base.metadata.tables[table_name].columns.keys())
        assert {"id", "owner_subject", "server_id", "created_at"} <= columns

    for name in (
        "capability-snapshot.schema.json",
        "capability-entity-revision.schema.json",
        "capability-event.schema.json",
    ):
        schema = json.loads((CONTRACT_ROOT / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False

    contract = _load_yaml(CONTRACT_ROOT / "mcp-capability-contract.yaml")
    assert contract["implementation_status"] == "storage_and_negotiation_only"
    assert contract["capabilities"]["tools"]["execution_status"] == (
        "production_read_only_pilot"
    )
    for capability in (
        "resources", "prompts", "roots", "sampling", "elicitation", "tasks", "logging"
    ):
        assert contract["capabilities"][capability]["execution_status"] == "not_enabled"

    openapi = _load_yaml(CONTRACT_ROOT / "openapi-control-plane.yaml")
    assert openapi["openapi"] == "3.1.0"
    assert set(openapi["paths"]) == {
        "/api/mcp/servers/{server_id}/oauth/discover",
        "/oauth/client-metadata.json",
    }
    assert openapi["x-implementation-status"] == (
        "oauth-discovery-control-plane-exposed"
    )
    assert openapi["x-capability-execution-enabled"] is False
    asyncapi = _load_yaml(CONTRACT_ROOT / "asyncapi.yaml")
    assert asyncapi["asyncapi"] == "3.0.0"
    assert asyncapi["x-implementation-status"] == "schema-only"
    assert contract["authorization_control_plane"]["credential_material_client_visible"] is False
    assert contract["authorization_control_plane"]["metadata_cache"] == (
        "expiry_and_issuer_pinning"
    )


def test_capability_snapshot_is_deterministic_idempotent_and_fenced() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    owner = "phase8-owner"
    server_id = "11111111-1111-4111-8111-111111111111"
    runtime_ids = (
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
    )
    with Session(engine) as db:
        server = McpServer(
            id=server_id,
            owner_subject=owner,
            origin="gateway",
            display_name="Phase 8 fixture",
            normalized_slug="phase-8-fixture",
            transport="streamable_http",
            status="online",
            trust_level="restricted",
            capabilities={},
            catalog_generation=3,
            policy_generation=1,
            version=1,
        )
        db.add(server)
        db.flush([server])
        for runtime_id in runtime_ids:
            db.add(
                McpRuntimeConnection(
                    id=runtime_id,
                    owner_subject=owner,
                    server_id=server_id,
                    connection_instance_id=f"connection-{runtime_id}",
                    supported_transports=["streamable_http"],
                    supported_protocol_versions=["2025-11-25"],
                    state="online",
                    acknowledged_catalog_generation=3,
                    meta={},
                )
            )
        db.flush()

        kwargs = {
            "owner_subject": owner,
            "server_id": server_id,
            "runtime_connection_id": runtime_ids[0],
            "source": "remote_initialize",
            "protocol_version": "2025-11-25",
            "catalog_generation": 3,
            "server_capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": True},
            },
            "client_capabilities": {},
            "negotiated_features": {
                "federated_server_capabilities": ["tools"],
                "observed_not_federated": ["resources"],
            },
        }
        expected_hash = capability_snapshot_hash(
            protocol_version=kwargs["protocol_version"],
            server_capabilities=kwargs["server_capabilities"],
            client_capabilities=kwargs["client_capabilities"],
            negotiated_features=kwargs["negotiated_features"],
        )
        first = record_capability_snapshot(db, **kwargs)
        db.flush()
        second = record_capability_snapshot(db, **kwargs)
        assert second.id == first.id
        assert first.capability_hash == expected_hash
        assert db.query(type(first)).count() == 1
        with pytest.raises(McpCapabilitySnapshotConflict):
            record_capability_snapshot(
                db,
                **{**kwargs, "server_capabilities": {"tools": {"listChanged": False}}},
            )
        third = record_capability_snapshot(
            db, **{**kwargs, "runtime_connection_id": runtime_ids[1]}
        )
        db.flush()
        assert third.id != first.id
        assert db.query(type(first)).count() == 2


def test_phase_eight_migration_contract() -> None:
    migration = (
        ROOT
        / "database/alembic/versions/20260726_0006_mcp_generalized_capability_control_plane.py"
    ).read_text(encoding="utf-8")
    sql = (
        ROOT / "database/migrations/007_mcp_generalized_capability_control_plane.sql"
    ).read_text(encoding="utf-8")
    baseline = (ROOT / "database/alembic/postgresql_baseline.sql").read_text(
        encoding="utf-8"
    )
    assert 'revision = "20260726_0006"' in migration
    assert 'down_revision = "20260726_0005"' in migration
    assert "partial Phase 8 capability schema detected" in migration
    assert "generalized MCP capability control-plane downgrade is not supported" in migration
    for table_name in sorted(CAPABILITY_TABLES):
        assert f'"{table_name}"' in migration
        assert f"CREATE TABLE {table_name}" in sql
        assert baseline.count(f"CREATE TABLE {table_name}") == 1
    for table_name in (
        "mcp_capability_snapshots",
        "mcp_capability_entity_revisions",
        "mcp_capability_events",
    ):
        assert f"ON {table_name}" in sql
    assert "gateway_mcp_capability_append_only_guard" in sql
    assert "RAISE EXCEPTION '%'" not in sql
    assert "RAISE EXCEPTION USING MESSAGE" in sql

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    assert CAPABILITY_TABLES <= set(inspector.get_table_names())
    for table_name in CAPABILITY_TABLES:
        expected = set(Base.metadata.tables[table_name].columns.keys())
        actual = {column["name"] for column in inspector.get_columns(table_name)}
        assert actual == expected
