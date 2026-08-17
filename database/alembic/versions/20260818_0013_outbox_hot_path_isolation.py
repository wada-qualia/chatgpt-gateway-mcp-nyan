from __future__ import annotations

from alembic import op
from gateway_api.migration_operations import create_index_concurrently
from sqlalchemy import inspect, text

revision = "20260818_0013"
down_revision = "20260811_0012"
deployment_compatibility = "expand"
branch_labels = None
depends_on = None

online_operations = (
    create_index_concurrently(
        name="ix_outbox_events_active_created_at",
        table="outbox_events",
        columns=("created_at", "id"),
        predicate="status IN ('pending', 'retry', 'processing')",
    ),
)

_INDEX_NAME = online_operations[0].name


def _create_missing_index(*, bootstrap: bool) -> None:
    inspector = inspect(op.get_bind())
    indexes = {item["name"] for item in inspector.get_indexes("outbox_events")}
    if _INDEX_NAME in indexes:
        return
    if op.get_bind().dialect.name == "postgresql" and not bootstrap:
        raise RuntimeError(f"online index operation was not applied: {_INDEX_NAME}")
    operation = online_operations[0]
    op.create_index(
        operation.name,
        operation.table,
        list(operation.columns),
        postgresql_where=text(operation.predicate),
        sqlite_where=text(operation.predicate),
    )


def _verify_schema() -> None:
    indexes = {item["name"] for item in inspect(op.get_bind()).get_indexes("outbox_events")}
    if _INDEX_NAME not in indexes:
        raise RuntimeError(f"Gateway outbox hot-path index missing: {_INDEX_NAME}")


def upgrade() -> None:
    bootstrap = bool(
        op.get_context().config.attributes.get("gateway_online_index_bootstrap")
    )
    _create_missing_index(bootstrap=bootstrap)
    _verify_schema()


def downgrade() -> None:
    raise RuntimeError("Gateway outbox hot-path isolation migration is irreversible")
