from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from gateway_api import schema_migrations
from gateway_api.database import Base
from gateway_api.migration_operations import (
    CreateIndexConcurrently,
    DropIndexConcurrently,
    create_index_concurrently,
    drop_index_concurrently,
)
from gateway_api.schema_migrations import (
    HEAD_REVISION,
    MigrationPlan,
    MigrationStatus,
    alembic_config,
    get_migration_plan,
    get_migration_status,
    migration_head,
    run_schema_migrations,
)
from sqlalchemy import create_engine, inspect, text

CAPACITY_INDEX_DROPS = (
    "ix_outbox_events_audit_event_id",
    "ix_outbox_events_published_at",
    "ix_outbox_events_lock_token",
    "ix_outbox_events_locked_by",
    "ix_outbox_events_subject",
    "ix_outbox_events_replayed_from_id",
)


def sqlite_engine(path: Path):
    return create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False},
    )


def test_deployment_plan_cli_is_read_only(monkeypatch, capsys) -> None:
    plan = MigrationPlan(
        current_revision="20260727_0010",
        head_revision=HEAD_REVISION,
        pending_revisions=(HEAD_REVISION,),
        compatibility=("expand",),
        safe_for_live_expand=True,
    )
    monkeypatch.setattr(schema_migrations, "get_migration_plan", lambda: plan)

    def unexpected_upgrade():
        raise AssertionError("deployment-plan must not run migrations")

    monkeypatch.setattr(
        schema_migrations,
        "run_schema_migrations",
        unexpected_upgrade,
    )

    assert schema_migrations.main(["deployment-plan"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["current_revision"] == "20260727_0010"
    assert payload["head_revision"] == HEAD_REVISION
    assert payload["pending_revisions"] == [HEAD_REVISION]
    assert payload["safe_for_live_expand"] is True


def test_validate_cli_is_read_only(monkeypatch, capsys) -> None:
    status = MigrationStatus(
        current_revisions=(HEAD_REVISION,),
        head_revision=HEAD_REVISION,
        at_head=True,
    )
    monkeypatch.setattr(
        schema_migrations,
        "validate_database_schema",
        lambda: status,
    )

    def unexpected_upgrade():
        raise AssertionError("validate must not run migrations")

    monkeypatch.setattr(
        schema_migrations,
        "run_schema_migrations",
        unexpected_upgrade,
    )

    assert schema_migrations.main(["validate"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["current_revision"] == HEAD_REVISION
    assert payload["at_head"] is True


def test_revision_forward_compatibility_is_strict() -> None:
    assert schema_migrations.revision_is_forward(
        "20260819_0001", HEAD_REVISION
    ) is True
    assert schema_migrations.revision_is_forward(HEAD_REVISION, HEAD_REVISION) is False
    assert schema_migrations.revision_is_forward(
        "20260727_0010", HEAD_REVISION
    ) is False
    assert schema_migrations.revision_is_forward("future", HEAD_REVISION) is False


def test_validate_database_schema_rejects_stamped_incomplete_database(
    tmp_path: Path,
) -> None:
    target_engine = sqlite_engine(tmp_path / "stamped-incomplete.sqlite")
    with target_engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
            {"revision": HEAD_REVISION},
        )

    with pytest.raises(RuntimeError, match="Database schema is missing tables"):
        schema_migrations.validate_database_schema(target_engine)


def test_live_deployment_plan_from_0011_declares_online_indexes(
    tmp_path: Path,
) -> None:
    target_engine = sqlite_engine(tmp_path / "deployment-plan.sqlite")
    config = alembic_config(str(target_engine.url))
    command.upgrade(config, "20260727_0011")

    plan = get_migration_plan(target_engine)

    assert plan.current_revision == "20260727_0011"
    assert plan.head_revision == HEAD_REVISION
    assert plan.pending_revisions == (
        "20260811_0012",
        "20260818_0013",
        HEAD_REVISION,
    )
    assert plan.compatibility == ("expand", "expand", "expand")
    assert plan.safe_for_live_expand is True
    assert plan.online_index_operations == (
        "ix_outbox_events_ready_claim",
        "ix_outbox_events_stale_claim",
        "ix_agent_tool_calls_lup_pending_schedule",
        "ix_outbox_events_active_created_at",
    ) + CAPACITY_INDEX_DROPS


def test_live_deployment_plan_from_0012_is_hot_path_index_only(
    tmp_path: Path,
) -> None:
    target_engine = sqlite_engine(tmp_path / "deployment-plan-0012.sqlite")
    command.upgrade(alembic_config(str(target_engine.url)), "20260811_0012")

    plan = get_migration_plan(target_engine)

    assert plan.current_revision == "20260811_0012"
    assert plan.pending_revisions == ("20260818_0013", HEAD_REVISION)
    assert plan.compatibility == ("expand", "expand")
    assert plan.safe_for_live_expand is True
    assert plan.online_index_operations == (
        "ix_outbox_events_active_created_at",
    ) + CAPACITY_INDEX_DROPS


def test_live_deployment_plan_from_0013_only_drops_capacity_indexes(
    tmp_path: Path,
) -> None:
    target_engine = sqlite_engine(tmp_path / "deployment-plan-0013.sqlite")
    command.upgrade(alembic_config(str(target_engine.url)), "20260818_0013")

    plan = get_migration_plan(target_engine)

    assert plan.current_revision == "20260818_0013"
    assert plan.pending_revisions == (HEAD_REVISION,)
    assert plan.compatibility == ("expand",)
    assert plan.safe_for_live_expand is True
    assert plan.online_index_operations == CAPACITY_INDEX_DROPS


def test_concurrent_index_declarations_are_strictly_typed() -> None:
    operation = create_index_concurrently(
        name="ix_example_pending",
        table="example_rows",
        columns=("created_at", "id"),
        predicate="status = 'pending'",
    )

    assert isinstance(operation, CreateIndexConcurrently)
    with pytest.raises(TypeError, match="non-empty tuple"):
        create_index_concurrently(
            name="ix_example_pending",
            table="example_rows",
            columns=[],  # type: ignore[arg-type]
            predicate="status = 'pending'",
        )
    with pytest.raises(ValueError, match="bounded safe expression"):
        create_index_concurrently(
            name="ix_example_pending",
            table="example_rows",
            columns=("id",),
            predicate="status = 'pending'; DROP TABLE users",
        )


def test_concurrent_index_drop_declarations_are_strictly_typed() -> None:
    operation = drop_index_concurrently(
        name="ix_example_history",
        table="example_rows",
    )

    assert isinstance(operation, DropIndexConcurrently)
    with pytest.raises(ValueError, match="concurrent index drop"):
        drop_index_concurrently(
            name="ix_example_history;drop",
            table="example_rows",
        )


def test_module_cli_loads_typed_online_operations_once(tmp_path: Path) -> None:
    database_path = tmp_path / "module-cli.sqlite"
    target_engine = sqlite_engine(database_path)
    command.upgrade(alembic_config(str(target_engine.url)), "20260727_0011")
    environment = dict(os.environ)
    environment["DATABASE_URL"] = f"sqlite:///{database_path}"
    environment["PYTHONPATH"] = os.pathsep.join(
        [
            str(Path(__file__).resolve().parents[1]),
            str(Path(__file__).resolve().parents[3] / "cli"),
        ]
    )

    result = subprocess.run(
        [sys.executable, "-m", "gateway_api.schema_migrations", "deployment-plan"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["online_index_operations"] == [
        "ix_outbox_events_ready_claim",
        "ix_outbox_events_stale_claim",
        "ix_agent_tool_calls_lup_pending_schedule",
        "ix_outbox_events_active_created_at",
    ] + list(CAPACITY_INDEX_DROPS)


def test_clean_database_upgrades_to_head(tmp_path: Path) -> None:
    target_engine = sqlite_engine(tmp_path / "clean.sqlite")

    first = run_schema_migrations(target_engine)
    second = run_schema_migrations(target_engine)
    status = get_migration_status(target_engine)

    assert first.current_revision == HEAD_REVISION
    assert first.at_head is True
    assert first.adopted_legacy_schema is False
    assert second.current_revision == HEAD_REVISION
    assert second.at_head is True
    assert status.current_revision == HEAD_REVISION
    assert status.at_head is True
    oauth_columns = {
        column["name"]
        for column in inspect(target_engine).get_columns("oauth_clients")
    }
    assert {
        "presentation_profile",
        "presentation_policy_generation",
        "presentation_mode",
        "presentation_capabilities",
        "workspace_plan",
        "allowed_tool_names",
        "updated_at",
    } <= oauth_columns
    server_columns = {
        column["name"]
        for column in inspect(target_engine).get_columns("mcp_servers")
    }
    invocation_columns = {
        column["name"]
        for column in inspect(target_engine).get_columns("mcp_invocations")
    }
    assert "local_server_id" in server_columns
    assert {
        "runtime_connection_id",
        "connection_instance_id",
        "thin_client_request_id",
    } <= invocation_columns
    capability_tables = {
        "mcp_capability_snapshots",
        "mcp_capability_entities",
        "mcp_capability_entity_revisions",
        "mcp_capability_subscriptions",
        "mcp_root_grants",
        "mcp_interaction_consents",
        "mcp_federated_tasks",
        "mcp_capability_events",
    }
    table_names = set(inspect(target_engine).get_table_names())
    assert capability_tables <= table_names
    assert "mcp_oauth_discovery_snapshots" in table_names
    traffic_columns = {
        column["name"]
        for column in inspect(target_engine).get_columns("agent_tool_calls")
    }
    assert {
        "request_characters",
        "response_characters",
        "estimated_input_tokens",
        "estimated_output_tokens",
        "traffic_delivery_status",
        "traffic_event_id",
        "traffic_observation_id",
        "traffic_next_attempt_at",
        "traffic_last_attempt_at",
    } <= traffic_columns
    agent_indexes = {
        item["name"]
        for item in inspect(target_engine).get_indexes("agent_tool_calls")
    }
    outbox_indexes = {
        item["name"] for item in inspect(target_engine).get_indexes("outbox_events")
    }
    assert "ix_agent_tool_calls_lup_pending_schedule" in agent_indexes
    assert {
        "ix_outbox_events_ready_claim",
        "ix_outbox_events_stale_claim",
    } <= outbox_indexes
    assert set(CAPACITY_INDEX_DROPS).isdisjoint(outbox_indexes)
    outbox_unique_constraints = {
        item["name"]
        for item in inspect(target_engine).get_unique_constraints("outbox_events")
    }
    assert "uq_outbox_event_audit_event" in outbox_unique_constraints


def test_legacy_database_is_adopted_and_upgraded(tmp_path: Path) -> None:
    target_engine = sqlite_engine(tmp_path / "legacy.sqlite")
    Base.metadata.create_all(target_engine)
    with target_engine.begin() as connection:
        connection.execute(text("DROP TABLE oauth_clients"))
        connection.execute(
            text(
                """
                CREATE TABLE oauth_clients (
                    client_id VARCHAR(255) PRIMARY KEY,
                    client_name VARCHAR(255) NOT NULL DEFAULT 'ChatGPT Connector',
                    redirect_uris JSON NOT NULL DEFAULT '[]',
                    scope TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

    result = run_schema_migrations(target_engine)

    assert result.current_revision == HEAD_REVISION
    assert result.at_head is True
    assert result.adopted_legacy_schema is True
    oauth_columns = {
        column["name"]
        for column in inspect(target_engine).get_columns("oauth_clients")
    }
    assert {
        "presentation_profile",
        "presentation_policy_generation",
        "presentation_mode",
        "presentation_capabilities",
        "workspace_plan",
        "allowed_tool_names",
        "updated_at",
    } <= oauth_columns
    server_columns = {
        column["name"]
        for column in inspect(target_engine).get_columns("mcp_servers")
    }
    invocation_columns = {
        column["name"]
        for column in inspect(target_engine).get_columns("mcp_invocations")
    }
    assert "local_server_id" in server_columns
    assert {
        "runtime_connection_id",
        "connection_instance_id",
        "thin_client_request_id",
    } <= invocation_columns
    capability_tables = {
        "mcp_capability_snapshots",
        "mcp_capability_entities",
        "mcp_capability_entity_revisions",
        "mcp_capability_subscriptions",
        "mcp_root_grants",
        "mcp_interaction_consents",
        "mcp_federated_tasks",
        "mcp_capability_events",
    }
    table_names = set(inspect(target_engine).get_table_names())
    assert capability_tables <= table_names
    assert "mcp_oauth_discovery_snapshots" in table_names


def test_phase_nine_presentation_negotiation_migration_is_complete() -> None:
    root = Path(__file__).resolve().parents[3]
    migration = (
        root
        / "database"
        / "alembic"
        / "versions"
        / "20260726_0009_mcp_presentation_negotiation.py"
    ).read_text(encoding="utf-8")
    sql = (
        root / "database" / "migrations" / "010_mcp_presentation_negotiation.sql"
    ).read_text(encoding="utf-8")
    baseline = (
        root / "database" / "alembic" / "postgresql_baseline.sql"
    ).read_text(encoding="utf-8")
    assert 'revision = "20260726_0009"' in migration
    assert 'down_revision = "20260726_0008"' in migration
    for column in (
        "presentation_mode",
        "presentation_capabilities",
        "workspace_plan",
    ):
        assert column in migration
        assert column in sql
        assert column in baseline
    for verification_kind in (
        "chatgpt_frozen_snapshot",
        "chatgpt_enterprise_refresh",
        "chatgpt_business_republish",
    ):
        assert verification_kind in migration
        assert verification_kind in sql
        assert verification_kind in baseline


def test_unrecognized_database_fails_closed(tmp_path: Path) -> None:
    target_engine = sqlite_engine(tmp_path / "foreign.sqlite")
    with target_engine.begin() as connection:
        connection.execute(text("CREATE TABLE foreign_table (id INTEGER PRIMARY KEY)"))

    with pytest.raises(RuntimeError, match="not a recognized Gateway schema"):
        run_schema_migrations(target_engine)


def test_migration_graph_has_single_expected_head() -> None:
    assert migration_head() == HEAD_REVISION


def test_postgresql_revision_guard_compares_json_as_jsonb() -> None:
    root = Path(__file__).resolve().parents[3]
    migration = (
        root
        / "database"
        / "alembic"
        / "versions"
        / "20260725_0004_mcp_revision_json_guard.py"
    ).read_text(encoding="utf-8")
    fresh_install_sources = [
        root / "database" / "migrations" / "002_mcp_federation_control_plane.sql",
        root
        / "database"
        / "alembic"
        / "versions"
        / "20260725_0001_current_schema_baseline.py",
        root
        / "database"
        / "alembic"
        / "versions"
        / "20260725_0003_startup_schema_compatibility.py",
    ]

    assert 'revision = "20260725_0004"' in migration
    assert 'down_revision = "20260725_0003"' in migration
    for field in ("input_schema", "output_schema", "annotations"):
        safe_comparison = (
            f"NEW.{field}::jsonb IS DISTINCT FROM OLD.{field}::jsonb"
        )
        unsafe_comparison = f"NEW.{field} IS DISTINCT FROM OLD.{field}"
        assert safe_comparison in migration
        assert unsafe_comparison not in migration
        for source in fresh_install_sources:
            source_text = source.read_text(encoding="utf-8")
            assert safe_comparison in source_text
            assert unsafe_comparison not in source_text
    assert "mcp_tool_revisions are append-only" in migration
    assert "immutable MCP tool revision payload cannot be modified" in migration
    assert "DROP TRIGGER" not in migration.upper()



def test_runtime_connection_identity_is_server_scoped() -> None:
    root = Path(__file__).resolve().parents[3]
    migration_path = (
        root
        / "database"
        / "alembic"
        / "versions"
        / "20260726_0005_mcp_runtime_connection_cardinality.py"
    )
    migration = migration_path.read_text(encoding="utf-8")
    model = (
        root / "services" / "gateway-api" / "gateway_api" / "models.py"
    ).read_text(encoding="utf-8")
    fresh_install_sources = [
        root / "database" / "migrations" / "002_mcp_federation_control_plane.sql",
        root / "database" / "alembic" / "postgresql_baseline.sql",
    ]
    expected = "UNIQUE (owner_subject, server_id, connection_instance_id)"
    legacy = "UNIQUE (owner_subject, connection_instance_id)"

    assert 'revision = "20260726_0005"' in migration
    assert 'down_revision = "20260725_0004"' in migration
    assert "GROUP BY owner_subject, server_id, connection_instance_id" in migration
    assert "HAVING COUNT(*) > 1" in migration
    assert f'_LEGACY_DEFINITION = "{legacy}"' in migration
    assert '"UNIQUE (owner_subject, server_id, connection_instance_id)"' in migration
    assert "current_definition == _EXPECTED_DEFINITION" in migration
    assert "current_definition != _LEGACY_DEFINITION" in migration
    assert '["owner_subject", "server_id", "connection_instance_id"]' in migration
    assert "downgrade is not supported" in migration
    assert '"owner_subject",' in model
    assert '"server_id",' in model
    assert '"connection_instance_id",' in model
    for source in fresh_install_sources:
        source_text = source.read_text(encoding="utf-8")
        assert expected in source_text
        assert legacy not in source_text


def main_module_path() -> str:
    import gateway_api.main as main_module

    return main_module.__file__


def test_application_startup_refuses_schema_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import gateway_api.main as main_module
    from fastapi.testclient import TestClient

    def incompatible_schema(*, allow_forward_revision: bool = False) -> MigrationStatus:
        assert allow_forward_revision is True
        raise RuntimeError(
            "Database revision 20260727_0010 does not match required Alembic head "
            f"{HEAD_REVISION}"
        )

    monkeypatch.setattr(
        main_module,
        "validate_database_schema",
        incompatible_schema,
    )
    app = main_module.create_app()

    with (
        pytest.raises(RuntimeError, match="does not match required Alembic head"),
        TestClient(app),
    ):
        pass

    assert app.state.initialization_status == "failed"
    assert app.state.database_at_head is False
    assert app.state.database_forward_compatible is False
    assert app.state.database_schema_valid is False
    assert app.state.database_compatible is False


def test_application_startup_never_executes_schema_upgrade() -> None:
    source = Path(main_module_path()).read_text(encoding="utf-8")

    assert "run_schema_migrations" not in source
    assert "validate_database_schema" in source
    assert "ReadinessCache" in source
