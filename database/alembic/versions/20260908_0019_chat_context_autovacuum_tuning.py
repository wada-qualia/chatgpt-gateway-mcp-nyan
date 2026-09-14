from __future__ import annotations

from alembic import op

revision = "20260908_0019"
down_revision = "20260908_0018"
deployment_compatibility = "expand"
branch_labels = None
depends_on = None

HOT_UPDATE_TABLES = ("agent_tool_calls", "command_sessions")
APPEND_ONLY_TABLES = ("file_change_sets",)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return

    for table in HOT_UPDATE_TABLES:
        op.execute(
            f"ALTER TABLE {table} SET (autovacuum_vacuum_scale_factor = 0.05)"
        )
    for table in APPEND_ONLY_TABLES:
        op.execute(
            f"ALTER TABLE {table} SET (autovacuum_vacuum_insert_scale_factor = 0.05)"
        )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return

    for table in APPEND_ONLY_TABLES:
        op.execute(
            f"ALTER TABLE {table} RESET (autovacuum_vacuum_insert_scale_factor)"
        )
    for table in reversed(HOT_UPDATE_TABLES):
        op.execute(f"ALTER TABLE {table} RESET (autovacuum_vacuum_scale_factor)")
