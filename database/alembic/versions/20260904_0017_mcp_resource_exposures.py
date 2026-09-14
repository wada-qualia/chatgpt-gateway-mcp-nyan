from __future__ import annotations

from alembic import op
from gateway_api import models
from sqlalchemy import inspect

revision = "20260904_0017"
down_revision = "20260828_0016"
deployment_compatibility = "expand"
branch_labels = None
depends_on = None

_TABLE = "mcp_capability_exposures"


def _verify_complete_schema() -> None:
    connection = op.get_bind()
    inspector = inspect(connection)
    if _TABLE not in inspector.get_table_names():
        raise RuntimeError(f"missing MCP resource exposure table: {_TABLE}")
    expected = set(models.Base.metadata.tables[_TABLE].columns.keys())
    actual = {column["name"] for column in inspector.get_columns(_TABLE)}
    missing = sorted(expected - actual)
    if missing:
        raise RuntimeError(
            f"partial MCP resource exposure schema {_TABLE}; missing columns: {missing}"
        )


def upgrade() -> None:
    connection = op.get_bind()
    if _TABLE not in inspect(connection).get_table_names():
        models.Base.metadata.tables[_TABLE].create(bind=connection, checkfirst=True)
    _verify_complete_schema()


def downgrade() -> None:
    connection = op.get_bind()
    if _TABLE in inspect(connection).get_table_names():
        models.Base.metadata.tables[_TABLE].drop(bind=connection, checkfirst=True)
