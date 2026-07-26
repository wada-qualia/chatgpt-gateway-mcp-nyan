from __future__ import annotations

from pathlib import Path

from alembic import op
from sqlalchemy import inspect

from gateway_api import models

revision = "20260726_0006"
down_revision = "20260726_0005"
branch_labels = None
depends_on = None

_TABLES = (
    "mcp_capability_snapshots",
    "mcp_capability_entities",
    "mcp_capability_entity_revisions",
    "mcp_capability_subscriptions",
    "mcp_root_grants",
    "mcp_interaction_consents",
    "mcp_federated_tasks",
    "mcp_capability_events",
)


def _verify_complete_schema() -> None:
    connection = op.get_bind()
    inspector = inspect(connection)
    for table_name in _TABLES:
        expected = set(models.Base.metadata.tables[table_name].columns.keys())
        actual = {
            column["name"] for column in inspector.get_columns(table_name)
        }
        missing = sorted(expected - actual)
        if missing:
            raise RuntimeError(
                f"partial Phase 8 capability table {table_name}; missing columns: {missing}"
            )


def upgrade() -> None:
    connection = op.get_bind()
    existing = set(inspect(connection).get_table_names()).intersection(_TABLES)
    if existing:
        if existing != set(_TABLES):
            raise RuntimeError(
                "partial Phase 8 capability schema detected: "
                f"found {sorted(existing)}"
            )
        _verify_complete_schema()
        return

    if connection.dialect.name == "postgresql":
        sql_path = (
            Path(__file__).resolve().parents[2]
            / "migrations"
            / "007_mcp_generalized_capability_control_plane.sql"
        )
        cursor = connection.connection.cursor()
        try:
            cursor.execute(sql_path.read_text(encoding="utf-8"))
        finally:
            cursor.close()
    else:
        for table_name in _TABLES:
            models.Base.metadata.tables[table_name].create(
                bind=connection,
                checkfirst=True,
            )
    _verify_complete_schema()


def downgrade() -> None:
    raise RuntimeError(
        "generalized MCP capability control-plane downgrade is not supported"
    )
