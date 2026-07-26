from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "20260726_0009"
down_revision = "20260726_0008"
branch_labels = None
depends_on = None

_OAUTH_COLUMNS = {
    "presentation_mode",
    "presentation_capabilities",
    "workspace_plan",
}
_VERIFICATION_KINDS = (
    "generic_tools_list_changed",
    "chatgpt_actions",
    "chatgpt_frozen_snapshot",
    "chatgpt_enterprise_refresh",
    "chatgpt_business_republish",
)


def _columns(table: str) -> set[str]:
    return {column["name"] for column in inspect(op.get_bind()).get_columns(table)}


def _checks(table: str) -> set[str]:
    return {
        str(constraint.get("name"))
        for constraint in inspect(op.get_bind()).get_check_constraints(table)
        if constraint.get("name")
    }


def _postgresql_sql() -> str:
    path = (
        Path(__file__).resolve().parents[2]
        / "migrations"
        / "010_mcp_presentation_negotiation.sql"
    )
    return path.read_text(encoding="utf-8")


def _execute_postgresql(sql: str) -> None:
    cursor = op.get_bind().connection.cursor()
    try:
        cursor.execute(sql)
    finally:
        cursor.close()


def _verify_complete_schema() -> None:
    missing = sorted(_OAUTH_COLUMNS - _columns("oauth_clients"))
    if missing:
        raise RuntimeError(
            f"partial MCP presentation-negotiation schema; missing={missing}"
        )
    checks = _checks("mcp_projection_verifications")
    if "ck_mcp_projection_verification_kind" not in checks:
        raise RuntimeError("MCP projection verification constraint is missing")


def upgrade() -> None:
    connection = op.get_bind()
    existing = _OAUTH_COLUMNS.intersection(_columns("oauth_clients"))
    if existing and existing != _OAUTH_COLUMNS:
        raise RuntimeError(
            f"partial MCP presentation-negotiation schema: {sorted(existing)}"
        )
    if connection.dialect.name == "postgresql":
        _execute_postgresql(_postgresql_sql())
    else:
        if not existing:
            op.add_column(
                "oauth_clients",
                sa.Column(
                    "presentation_mode",
                    sa.String(length=40),
                    nullable=False,
                    server_default="native_projected",
                ),
            )
            op.add_column(
                "oauth_clients",
                sa.Column(
                    "presentation_capabilities",
                    sa.JSON(),
                    nullable=False,
                    server_default='["native_tools"]',
                ),
            )
            op.add_column(
                "oauth_clients",
                sa.Column(
                    "workspace_plan",
                    sa.String(length=24),
                    nullable=False,
                    server_default="none",
                ),
            )
            op.create_index(
                "ix_oauth_clients_presentation_mode",
                "oauth_clients",
                ["presentation_mode"],
            )
            op.create_index(
                "ix_oauth_clients_workspace_plan",
                "oauth_clients",
                ["workspace_plan"],
            )
        with op.batch_alter_table("mcp_projection_verifications") as batch:
            if "ck_mcp_projection_verification_kind" in _checks(
                "mcp_projection_verifications"
            ):
                batch.drop_constraint(
                    "ck_mcp_projection_verification_kind", type_="check"
                )
            values = ", ".join(f"'{value}'" for value in _VERIFICATION_KINDS)
            batch.create_check_constraint(
                "ck_mcp_projection_verification_kind",
                f"verification_kind in ({values})",
            )
    _verify_complete_schema()


def downgrade() -> None:
    raise RuntimeError("MCP presentation-negotiation downgrade is not supported")
