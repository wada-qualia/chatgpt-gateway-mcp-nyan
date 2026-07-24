from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "20260725_0002"
down_revision = "20260725_0001"
branch_labels = None
depends_on = None


def _add_sqlite_columns() -> None:
    connection = op.get_bind()
    existing = {
        column["name"] for column in inspect(connection).get_columns("oauth_clients")
    }
    columns = {
        "presentation_profile": sa.Column(
            "presentation_profile", sa.String(40), nullable=True
        ),
        "presentation_policy_generation": sa.Column(
            "presentation_policy_generation", sa.Integer(), nullable=True
        ),
        "allowed_tool_names": sa.Column(
            "allowed_tool_names", sa.JSON(), nullable=True
        ),
        "updated_at": sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=True
        ),
    }
    for name, column in columns.items():
        if name not in existing:
            op.add_column("oauth_clients", column)
    indexes = {index["name"] for index in inspect(connection).get_indexes("oauth_clients")}
    if "ix_oauth_clients_presentation_profile" not in indexes:
        op.create_index(
            "ix_oauth_clients_presentation_profile",
            "oauth_clients",
            ["presentation_profile"],
        )


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        sql_path = (
            Path(__file__).resolve().parents[2]
            / "migrations"
            / "006_mcp_chatgpt_projections.sql"
        )
        cursor = connection.connection.cursor()
        try:
            cursor.execute(sql_path.read_text(encoding="utf-8"))
        finally:
            cursor.close()
        connection.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_oauth_clients_presentation_profile "
            "ON oauth_clients (presentation_profile)"
        )
        return
    _add_sqlite_columns()


def downgrade() -> None:
    pass
