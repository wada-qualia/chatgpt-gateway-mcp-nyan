from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from gateway_api.migration_operations import create_index_concurrently
from sqlalchemy import inspect, text

revision = "20260811_0012"
down_revision = "20260727_0011"
deployment_compatibility = "expand"
branch_labels = None
depends_on = None

online_operations = (
    create_index_concurrently(
        name="ix_outbox_events_ready_claim",
        table="outbox_events",
        columns=("available_at", "created_at", "id"),
        predicate="status IN ('pending', 'retry')",
    ),
    create_index_concurrently(
        name="ix_outbox_events_stale_claim",
        table="outbox_events",
        columns=("locked_at", "id"),
        predicate="status = 'processing' AND locked_at IS NOT NULL",
    ),
    create_index_concurrently(
        name="ix_agent_tool_calls_lup_pending_schedule",
        table="agent_tool_calls",
        columns=("created_at", "id"),
        predicate="traffic_delivery_status = 'pending'",
    ),
)

_SCHEDULING_COLUMNS = {
    "traffic_next_attempt_at",
    "traffic_last_attempt_at",
}
_INDEXES = {operation.name for operation in online_operations}


def _create_missing_indexes(*, bootstrap: bool) -> None:
    inspector = inspect(op.get_bind())
    table_indexes = {
        "outbox_events": {
            item["name"] for item in inspector.get_indexes("outbox_events")
        },
        "agent_tool_calls": {
            item["name"] for item in inspector.get_indexes("agent_tool_calls")
        },
    }
    for operation in online_operations:
        if operation.name in table_indexes[operation.table]:
            continue
        if op.get_bind().dialect.name == "postgresql" and not bootstrap:
            raise RuntimeError(
                f"online index operation was not applied: {operation.name}"
            )
        op.create_index(
            operation.name,
            operation.table,
            list(operation.columns),
            postgresql_where=text(operation.predicate),
            sqlite_where=text(operation.predicate),
        )


def _upgrade_delivery_status_constraint() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    definitions = {
        item["name"]: str(item.get("sqltext") or "")
        for item in inspect(connection).get_check_constraints("agent_tool_calls")
    }
    current = definitions.get("ck_agent_tool_calls_traffic_delivery_status", "")
    if "dead_letter" in current:
        return
    op.execute(
        "ALTER TABLE agent_tool_calls "
        "DROP CONSTRAINT IF EXISTS ck_agent_tool_calls_traffic_delivery_status"
    )
    op.execute(
        "ALTER TABLE agent_tool_calls "
        "ADD CONSTRAINT ck_agent_tool_calls_traffic_delivery_status "
        "CHECK (traffic_delivery_status IN "
        "('not_recorded', 'pending', 'delivered', 'disabled', 'dead_letter')) "
        "NOT VALID"
    )
    op.execute(
        "ALTER TABLE agent_tool_calls "
        "VALIDATE CONSTRAINT ck_agent_tool_calls_traffic_delivery_status"
    )


def _verify_schema() -> None:
    inspector = inspect(op.get_bind())
    columns = {
        item["name"] for item in inspector.get_columns("agent_tool_calls")
    }
    missing_columns = _SCHEDULING_COLUMNS - columns
    if missing_columns:
        raise RuntimeError(
            f"LUP scheduling columns missing: {sorted(missing_columns)}"
        )
    indexes = {
        item["name"]
        for table in ("outbox_events", "agent_tool_calls")
        for item in inspector.get_indexes(table)
    }
    missing_indexes = _INDEXES - indexes
    if missing_indexes:
        raise RuntimeError(
            f"Gateway latency indexes missing: {sorted(missing_indexes)}"
        )
    if op.get_bind().dialect.name == "postgresql":
        constraints = {
            item["name"]: str(item.get("sqltext") or "")
            for item in inspector.get_check_constraints("agent_tool_calls")
        }
        if "dead_letter" not in constraints.get(
            "ck_agent_tool_calls_traffic_delivery_status", ""
        ):
            raise RuntimeError("LUP dead-letter delivery status is not allowed")


def upgrade() -> None:
    existing = {
        item["name"]
        for item in inspect(op.get_bind()).get_columns("agent_tool_calls")
    }
    present = existing & _SCHEDULING_COLUMNS
    if present and present != _SCHEDULING_COLUMNS:
        raise RuntimeError(f"partial LUP scheduling schema: {sorted(present)}")
    if not present:
        op.add_column(
            "agent_tool_calls",
            sa.Column(
                "traffic_next_attempt_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
        )
        op.add_column(
            "agent_tool_calls",
            sa.Column(
                "traffic_last_attempt_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
        )
    _upgrade_delivery_status_constraint()
    bootstrap = bool(
        op.get_context().config.attributes.get("gateway_online_index_bootstrap")
    )
    _create_missing_indexes(bootstrap=bootstrap)
    _verify_schema()


def downgrade() -> None:
    raise RuntimeError("Gateway latency scheduling migration is irreversible")
