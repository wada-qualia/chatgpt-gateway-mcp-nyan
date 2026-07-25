from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from gateway_api.database import Base
from gateway_api.schema_migrations import (
    HEAD_REVISION,
    get_migration_status,
    migration_head,
    run_schema_migrations,
)


def sqlite_engine(path: Path):
    return create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False},
    )


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


def test_application_startup_fails_when_migrations_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastapi.testclient import TestClient

    import gateway_api.main as main_module

    def fail_migrations():
        raise RuntimeError("migration failed")

    monkeypatch.setattr(main_module, "run_schema_migrations", fail_migrations)
    app = main_module.create_app()

    with pytest.raises(RuntimeError, match="migration failed"):
        with TestClient(app):
            pass

    assert app.state.initialization_status == "failed"
    assert app.state.database_at_head is False
