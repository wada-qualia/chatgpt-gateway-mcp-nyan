from __future__ import annotations

from pathlib import Path

from alembic import op
from sqlalchemy import inspect

from gateway_api import models

revision = "20260726_0007"
down_revision = "20260726_0006"
branch_labels = None
depends_on = None

_TABLE = "mcp_oauth_discovery_snapshots"


def _verify_complete_schema() -> None:
    connection = op.get_bind()
    expected = set(models.Base.metadata.tables[_TABLE].columns.keys())
    actual = {column["name"] for column in inspect(connection).get_columns(_TABLE)}
    missing = sorted(expected - actual)
    if missing:
        raise RuntimeError(
            f"partial MCP OAuth discovery schema; missing columns: {missing}"
        )


def upgrade() -> None:
    connection = op.get_bind()
    if _TABLE in set(inspect(connection).get_table_names()):
        _verify_complete_schema()
        return
    if connection.dialect.name == "postgresql":
        sql_path = (
            Path(__file__).resolve().parents[2]
            / "migrations"
            / "008_mcp_oauth_discovery.sql"
        )
        cursor = connection.connection.cursor()
        try:
            cursor.execute(sql_path.read_text(encoding="utf-8"))
        finally:
            cursor.close()
    else:
        models.Base.metadata.tables[_TABLE].create(bind=connection, checkfirst=True)
    _verify_complete_schema()


def downgrade() -> None:
    raise RuntimeError("MCP OAuth discovery snapshot downgrade is not supported")
