from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "20260828_0016"
down_revision = "20260828_0015"
deployment_compatibility = "expand"
branch_labels = None
depends_on = None

_CHECK_NAME = "ck_oauth_client_chat_context_mode"
_INDEX_NAME = "ix_oauth_clients_chat_context_mode"
_CHECK_EXPRESSION = "chat_context_mode IN ('off', 'optional', 'required')"


def _columns() -> set[str]:
    return {
        column["name"]
        for column in inspect(op.get_bind()).get_columns("oauth_clients")
    }


def _checks() -> set[str]:
    return {
        str(item.get("name"))
        for item in inspect(op.get_bind()).get_check_constraints("oauth_clients")
        if item.get("name")
    }


def _indexes() -> set[str]:
    return {
        str(item.get("name"))
        for item in inspect(op.get_bind()).get_indexes("oauth_clients")
        if item.get("name")
    }


def _verify() -> None:
    inspector = inspect(op.get_bind())
    columns = {
        column["name"]: column
        for column in inspector.get_columns("oauth_clients")
    }
    column = columns.get("chat_context_mode")
    if column is None:
        raise RuntimeError("oauth_clients.chat_context_mode is missing")
    if column["nullable"] is not False:
        raise RuntimeError("oauth_clients.chat_context_mode must be non-nullable")
    checks = {
        item.get("name")
        for item in inspector.get_check_constraints("oauth_clients")
    }
    if _CHECK_NAME not in checks:
        raise RuntimeError("oauth_clients chat context mode constraint is missing")
    indexes = {
        item.get("name")
        for item in inspector.get_indexes("oauth_clients")
    }
    if _INDEX_NAME not in indexes:
        raise RuntimeError("oauth_clients chat context mode index is missing")


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        missing_column = "chat_context_mode" not in _columns()
        missing_check = _CHECK_NAME not in _checks()
        if missing_column or missing_check:
            with op.batch_alter_table("oauth_clients", recreate="always") as batch:
                if missing_column:
                    batch.add_column(
                        sa.Column(
                            "chat_context_mode",
                            sa.String(length=16),
                            nullable=False,
                            server_default=sa.text("'off'"),
                        )
                    )
                if missing_check:
                    batch.create_check_constraint(
                        _CHECK_NAME,
                        _CHECK_EXPRESSION,
                    )
    else:
        if "chat_context_mode" not in _columns():
            op.add_column(
                "oauth_clients",
                sa.Column(
                    "chat_context_mode",
                    sa.String(length=16),
                    nullable=False,
                    server_default=sa.text("'off'"),
                ),
            )
        if _CHECK_NAME not in _checks():
            op.create_check_constraint(
                _CHECK_NAME,
                "oauth_clients",
                _CHECK_EXPRESSION,
            )
    if _INDEX_NAME not in _indexes():
        op.create_index(
            _INDEX_NAME,
            "oauth_clients",
            ["chat_context_mode"],
            unique=False,
        )
    _verify()


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if _INDEX_NAME in _indexes():
        op.drop_index(_INDEX_NAME, table_name="oauth_clients")
    if dialect == "sqlite":
        if "chat_context_mode" in _columns():
            with op.batch_alter_table("oauth_clients", recreate="always") as batch:
                if _CHECK_NAME in _checks():
                    batch.drop_constraint(_CHECK_NAME, type_="check")
                batch.drop_column("chat_context_mode")
        return
    if _CHECK_NAME in _checks():
        op.drop_constraint(_CHECK_NAME, "oauth_clients", type_="check")
    if "chat_context_mode" in _columns():
        op.drop_column("oauth_clients", "chat_context_mode")
