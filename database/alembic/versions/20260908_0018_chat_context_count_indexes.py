from __future__ import annotations

from alembic import op
from gateway_api.migration_operations import create_index_concurrently
from sqlalchemy import inspect, text

revision = "20260908_0018"
down_revision = "20260904_0017"
deployment_compatibility = "expand"
branch_labels = None
depends_on = None
online_operations_prerequisite_revision = down_revision

online_operations = tuple(
    create_index_concurrently(
        name=f"ix_{table}_owner_chat_context",
        table=table,
        columns=("owner_subject", "chat_context_id"),
        predicate="chat_context_id IS NOT NULL",
    )
    for table in ("agent_tool_calls", "command_sessions", "file_change_sets")
)


def upgrade() -> None:
    bootstrap = bool(
        op.get_context().config.attributes.get("gateway_online_index_bootstrap")
    )
    connection = op.get_bind()
    for operation in online_operations:
        indexes = {
            item["name"] for item in inspect(connection).get_indexes(operation.table)
        }
        if operation.name in indexes:
            continue
        if connection.dialect.name == "postgresql" and not bootstrap:
            raise RuntimeError(f"online index operation was not applied: {operation.name}")
        op.create_index(
            operation.name,
            operation.table,
            list(operation.columns),
            postgresql_where=text(operation.predicate),
            sqlite_where=text(operation.predicate),
        )


def downgrade() -> None:
    connection = op.get_bind()
    for operation in reversed(online_operations):
        indexes = {
            item["name"] for item in inspect(connection).get_indexes(operation.table)
        }
        if operation.name in indexes:
            op.drop_index(operation.name, table_name=operation.table)
