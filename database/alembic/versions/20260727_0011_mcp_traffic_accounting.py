from __future__ import annotations

from pathlib import Path

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "20260727_0011"
down_revision = "20260727_0010"
deployment_compatibility = "expand"
branch_labels = None
depends_on = None

_COLUMNS = {
    "request_characters",
    "response_characters",
    "estimated_input_tokens",
    "estimated_output_tokens",
    "traffic_task_usage_id",
    "traffic_correlation_id",
    "traffic_event_id",
    "traffic_observation_id",
    "traffic_delivery_status",
    "traffic_attempt_count",
    "traffic_receipt_status",
    "traffic_last_error_code",
    "traffic_delivered_at",
}


def _verify_schema() -> None:
    inspector = inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("agent_tool_calls")}
    missing = _COLUMNS - columns
    if missing:
        raise RuntimeError(f"MCP traffic accounting columns missing: {sorted(missing)}")
    indexes = {item["name"] for item in inspector.get_indexes("agent_tool_calls")}
    if "ix_agent_tool_calls_traffic_delivery_status" not in indexes:
        raise RuntimeError("MCP traffic delivery index is missing")


def _upgrade_portable() -> None:
    with op.batch_alter_table("agent_tool_calls") as batch:
        batch.add_column(sa.Column("request_characters", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("response_characters", sa.Integer(), nullable=True))
        batch.add_column(
            sa.Column("estimated_input_tokens", sa.Integer(), nullable=True)
        )
        batch.add_column(
            sa.Column("estimated_output_tokens", sa.Integer(), nullable=True)
        )
        batch.add_column(
            sa.Column("traffic_task_usage_id", sa.String(36), nullable=True)
        )
        batch.add_column(
            sa.Column("traffic_correlation_id", sa.String(36), nullable=True)
        )
        batch.add_column(sa.Column("traffic_event_id", sa.String(36), nullable=True))
        batch.add_column(
            sa.Column("traffic_observation_id", sa.String(36), nullable=True)
        )
        batch.add_column(
            sa.Column(
                "traffic_delivery_status",
                sa.String(32),
                nullable=False,
                server_default="not_recorded",
            )
        )
        batch.add_column(
            sa.Column(
                "traffic_attempt_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch.add_column(
            sa.Column("traffic_receipt_status", sa.String(32), nullable=True)
        )
        batch.add_column(
            sa.Column("traffic_last_error_code", sa.String(128), nullable=True)
        )
        batch.add_column(
            sa.Column("traffic_delivered_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.create_unique_constraint(
            "uq_agent_tool_calls_traffic_task_usage_id", ["traffic_task_usage_id"]
        )
        batch.create_unique_constraint(
            "uq_agent_tool_calls_traffic_correlation_id", ["traffic_correlation_id"]
        )
        batch.create_unique_constraint(
            "uq_agent_tool_calls_traffic_event_id", ["traffic_event_id"]
        )
        batch.create_unique_constraint(
            "uq_agent_tool_calls_traffic_observation_id", ["traffic_observation_id"]
        )
    op.create_index(
        "ix_agent_tool_calls_traffic_delivery_status",
        "agent_tool_calls",
        ["traffic_delivery_status"],
    )


def upgrade() -> None:
    existing = {
        column["name"]
        for column in inspect(op.get_bind()).get_columns("agent_tool_calls")
    }
    present = existing & _COLUMNS
    if present and present != _COLUMNS:
        raise RuntimeError(f"partial MCP traffic accounting schema: {sorted(present)}")
    if not present:
        if op.get_bind().dialect.name == "postgresql":
            root = Path(__file__).resolve().parents[2]
            op.execute(
                (root / "migrations" / "012_mcp_traffic_accounting.sql").read_text()
            )
        else:
            _upgrade_portable()
    _verify_schema()


def downgrade() -> None:
    raise RuntimeError("MCP traffic accounting migration is intentionally irreversible")
