from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "20260726_0008"
down_revision = "20260726_0007"
branch_labels = None
depends_on = None

_SERVER_COLUMNS = {"sanitized_instructions", "instructions_sha256"}
_REVISION_COLUMNS = {"icons", "execution", "component_meta"}


def _columns(table: str) -> set[str]:
    return {column["name"] for column in inspect(op.get_bind()).get_columns(table)}


def _verify_complete_schema() -> None:
    server_missing = sorted(_SERVER_COLUMNS - _columns("mcp_servers"))
    revision_missing = sorted(_REVISION_COLUMNS - _columns("mcp_tool_revisions"))
    if server_missing or revision_missing:
        raise RuntimeError(
            "partial MCP rich-fidelity schema; "
            f"server missing={server_missing}, revision missing={revision_missing}"
        )


def _postgresql_sql() -> str:
    path = (
        Path(__file__).resolve().parents[2] / "migrations" / "009_mcp_rich_fidelity.sql"
    )
    return path.read_text(encoding="utf-8")


def _execute_postgresql(sql: str) -> None:
    cursor = op.get_bind().connection.cursor()
    try:
        cursor.execute(sql)
    finally:
        cursor.close()


def upgrade() -> None:
    connection = op.get_bind()
    server_existing = _SERVER_COLUMNS.intersection(_columns("mcp_servers"))
    revision_existing = _REVISION_COLUMNS.intersection(_columns("mcp_tool_revisions"))
    if server_existing and server_existing != _SERVER_COLUMNS:
        raise RuntimeError(
            f"partial MCP rich-fidelity server schema: {sorted(server_existing)}"
        )
    if revision_existing and revision_existing != _REVISION_COLUMNS:
        raise RuntimeError(
            f"partial MCP rich-fidelity revision schema: {sorted(revision_existing)}"
        )
    sql = _postgresql_sql()
    if connection.dialect.name == "postgresql":
        if not server_existing and not revision_existing:
            _execute_postgresql(sql)
        elif (
            server_existing == _SERVER_COLUMNS
            and revision_existing == _REVISION_COLUMNS
        ):
            guard = sql[sql.index("CREATE OR REPLACE FUNCTION") :]
            _execute_postgresql(guard)
        else:
            raise RuntimeError("partial MCP rich-fidelity schema across tables")
    else:
        if not server_existing:
            op.add_column(
                "mcp_servers",
                sa.Column(
                    "sanitized_instructions",
                    sa.Text(),
                    nullable=False,
                    server_default="",
                ),
            )
            op.add_column(
                "mcp_servers",
                sa.Column("instructions_sha256", sa.String(length=64), nullable=True),
            )
        if not revision_existing:
            op.add_column(
                "mcp_tool_revisions",
                sa.Column("icons", sa.JSON(), nullable=False, server_default="[]"),
            )
            op.add_column(
                "mcp_tool_revisions",
                sa.Column("execution", sa.JSON(), nullable=False, server_default="{}"),
            )
            op.add_column(
                "mcp_tool_revisions",
                sa.Column(
                    "component_meta", sa.JSON(), nullable=False, server_default="{}"
                ),
            )
    _verify_complete_schema()


def downgrade() -> None:
    raise RuntimeError("MCP rich-fidelity downgrade is not supported")
