from __future__ import annotations

from alembic import op
from sqlalchemy import inspect, text

revision = "20260908_0020"
down_revision = "20260908_0019"
deployment_compatibility = "expand"
branch_labels = None
depends_on = None

_TABLE = "mcp_capability_exposures"
_CONSTRAINT = "ck_mcp_capability_exposure_kind"
_OLD_EXPRESSION = "entity_kind in ('resource', 'resource_template')"
_NEW_EXPRESSION = "entity_kind in ('resource', 'resource_template', 'prompt')"


def _replace_constraint(expression: str) -> None:
    connection = op.get_bind()
    inspector = inspect(connection)
    if _TABLE not in inspector.get_table_names():
        raise RuntimeError(f"missing MCP capability exposure table: {_TABLE}")
    constraints = {
        item.get("name"): item for item in inspector.get_check_constraints(_TABLE)
    }
    if _CONSTRAINT not in constraints:
        raise RuntimeError(f"missing MCP capability exposure constraint: {_CONSTRAINT}")
    if connection.dialect.name == "sqlite":
        with op.batch_alter_table(_TABLE, recreate="always") as batch:
            batch.drop_constraint(_CONSTRAINT, type_="check")
            batch.create_check_constraint(_CONSTRAINT, expression)
        return
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, expression)


def upgrade() -> None:
    _replace_constraint(_NEW_EXPRESSION)


def downgrade() -> None:
    connection = op.get_bind()
    if _TABLE in inspect(connection).get_table_names():
        prompt_row = connection.execute(
            text(
                "SELECT 1 FROM mcp_capability_exposures "
                "WHERE entity_kind = 'prompt' LIMIT 1"
            )
        ).first()
        if prompt_row is not None:
            raise RuntimeError(
                "cannot restore resource-only exposure constraint while prompt exposures exist"
            )
    _replace_constraint(_OLD_EXPRESSION)
