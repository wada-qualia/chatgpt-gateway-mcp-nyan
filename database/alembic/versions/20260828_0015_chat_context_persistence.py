from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect, text

revision = "20260828_0015"
down_revision = "20260818_0014"
deployment_compatibility = "expand"
branch_labels = None
depends_on = None

_CONTEXT_TABLES = {
    "chat_contexts",
    "chat_context_aliases",
    "chat_context_events",
}
_ATTRIBUTION_TABLES = (
    "agent_tool_calls",
    "command_sessions",
    "file_change_sets",
)
_ATTRIBUTION_FKS = {
    "agent_tool_calls": "fk_agent_tool_call_chat_context",
    "command_sessions": "fk_command_session_chat_context",
    "file_change_sets": "fk_file_change_set_chat_context",
}


def _code_check_expression() -> str:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        return "char_length(code) = 4 AND code ~ '^[A-Za-z0-9]{4}$'"
    if dialect == "sqlite":
        return "length(code) = 4 AND code NOT GLOB '*[^A-Za-z0-9]*'"
    return "length(code) = 4"


def _create_context_tables() -> None:
    op.create_table(
        "chat_contexts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_subject", sa.String(length=255), nullable=False),
        sa.Column("host_kind", sa.String(length=40), nullable=False),
        sa.Column("state", sa.String(length=40), nullable=False),
        sa.Column("project_ref", sa.String(length=255), nullable=True),
        sa.Column("client_nonce", sa.String(length=128), nullable=True),
        sa.Column("conversation_ref_hmac", sa.String(length=64), nullable=True),
        sa.Column("conversation_key_version", sa.Integer(), nullable=True),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "host_kind = 'chatgpt'",
            name="ck_chat_context_host_kind",
        ),
        sa.CheckConstraint(
            "state in ('active', 'dormant', 'closed')",
            name="ck_chat_context_state",
        ),
        sa.CheckConstraint(
            "generation >= 0",
            name="ck_chat_context_generation",
        ),
        sa.CheckConstraint(
            "conversation_key_version IS NULL OR conversation_key_version >= 1",
            name="ck_chat_context_conversation_key_version",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "owner_subject", name="uq_chat_context_id_owner"),
    )
    op.create_index(
        "ix_chat_contexts_owner_subject",
        "chat_contexts",
        ["owner_subject"],
        unique=False,
    )
    op.create_index(
        "ix_chat_contexts_state",
        "chat_contexts",
        ["state"],
        unique=False,
    )
    op.create_index(
        "ix_chat_context_owner_state",
        "chat_contexts",
        ["owner_subject", "state"],
        unique=False,
    )
    op.create_index(
        "uq_chat_context_owner_client_nonce",
        "chat_contexts",
        ["owner_subject", "client_nonce"],
        unique=True,
        postgresql_where=text("client_nonce IS NOT NULL"),
        sqlite_where=text("client_nonce IS NOT NULL"),
    )
    op.create_index(
        "uq_chat_context_owner_host_conversation",
        "chat_contexts",
        ["owner_subject", "host_kind", "conversation_ref_hmac"],
        unique=True,
        postgresql_where=text("conversation_ref_hmac IS NOT NULL"),
        sqlite_where=text("conversation_ref_hmac IS NOT NULL"),
    )
    op.create_table(
        "chat_context_aliases",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("context_id", sa.String(length=36), nullable=False),
        sa.Column("owner_subject", sa.String(length=255), nullable=False),
        sa.Column("code", sa.String(length=4), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("quarantine_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_alias_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            _code_check_expression(),
            name="ck_chat_context_alias_code_format",
        ),
        sa.CheckConstraint(
            "status in ('active', 'quarantined', 'released', 'revoked')",
            name="ck_chat_context_alias_status",
        ),
        sa.CheckConstraint(
            "generation >= 1",
            name="ck_chat_context_alias_generation",
        ),
        sa.ForeignKeyConstraint(
            ["context_id", "owner_subject"],
            ["chat_contexts.id", "chat_contexts.owner_subject"],
            name="fk_chat_context_alias_context_owner",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["replaced_by_alias_id"],
            ["chat_context_aliases.id"],
            name="fk_chat_context_alias_replacement",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "owner_subject",
            "code",
            name="uq_chat_context_alias_owner_code",
        ),
        sa.UniqueConstraint(
            "context_id",
            "generation",
            name="uq_chat_context_alias_context_generation",
        ),
    )
    for column in (
        "context_id",
        "owner_subject",
        "code",
        "status",
        "expires_at",
        "quarantine_until",
    ):
        op.create_index(
            f"ix_chat_context_aliases_{column}",
            "chat_context_aliases",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_chat_context_alias_owner_context",
        "chat_context_aliases",
        ["owner_subject", "context_id"],
        unique=False,
    )
    op.create_index(
        "uq_chat_context_alias_live_code",
        "chat_context_aliases",
        ["code"],
        unique=True,
        postgresql_where=text("status IN ('active', 'quarantined')"),
        sqlite_where=text("status IN ('active', 'quarantined')"),
    )
    op.create_index(
        "uq_chat_context_alias_active_context",
        "chat_context_aliases",
        ["context_id"],
        unique=True,
        postgresql_where=text("status = 'active'"),
        sqlite_where=text("status = 'active'"),
    )
    op.create_table(
        "chat_context_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("context_id", sa.String(length=36), nullable=False),
        sa.Column("owner_subject", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("alias_generation", sa.Integer(), nullable=True),
        sa.Column("actor_kind", sa.String(length=40), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "action in ('created', 'issued', 'renewed', 'bound', 'expired', "
            "'quarantined', 'rotated', 'released', 'revoked', 'closed')",
            name="ck_chat_context_event_action",
        ),
        sa.CheckConstraint(
            "actor_kind in ('browser_extension', 'mcp', 'gateway', 'operator')",
            name="ck_chat_context_event_actor_kind",
        ),
        sa.CheckConstraint(
            "alias_generation IS NULL OR alias_generation >= 1",
            name="ck_chat_context_event_alias_generation",
        ),
        sa.ForeignKeyConstraint(
            ["context_id", "owner_subject"],
            ["chat_contexts.id", "chat_contexts.owner_subject"],
            name="fk_chat_context_event_context_owner",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("context_id", "owner_subject", "action"):
        op.create_index(
            f"ix_chat_context_events_{column}",
            "chat_context_events",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_chat_context_event_context_created",
        "chat_context_events",
        ["context_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_chat_context_event_owner_created",
        "chat_context_events",
        ["owner_subject", "created_at"],
        unique=False,
    )


def _add_attribution_columns() -> None:
    dialect = op.get_bind().dialect.name
    for table_name in _ATTRIBUTION_TABLES:
        if dialect == "postgresql":
            op.add_column(
                table_name,
                sa.Column("chat_context_id", sa.String(length=36), nullable=True),
            )
            op.execute(
                f"ALTER TABLE {table_name} ADD CONSTRAINT "
                f"{_ATTRIBUTION_FKS[table_name]} FOREIGN KEY (chat_context_id) "
                "REFERENCES chat_contexts (id) ON DELETE RESTRICT NOT VALID"
            )
        else:
            op.add_column(
                table_name,
                sa.Column(
                    "chat_context_id",
                    sa.String(length=36),
                    sa.ForeignKey(
                        "chat_contexts.id",
                        name=_ATTRIBUTION_FKS[table_name],
                        ondelete="RESTRICT",
                    ),
                    nullable=True,
                ),
            )


def _ensure_base62_constraint() -> None:
    connection = op.get_bind()
    checks = {
        item.get("name"): str(item.get("sqltext") or "")
        for item in inspect(connection).get_check_constraints("chat_context_aliases")
    }
    if "ck_chat_context_alias_code_format" in checks:
        return
    dialect = connection.dialect.name
    if dialect == "sqlite":
        with op.batch_alter_table("chat_context_aliases", recreate="always") as batch:
            if "ck_chat_context_alias_code_length" in checks:
                batch.drop_constraint(
                    "ck_chat_context_alias_code_length",
                    type_="check",
                )
            batch.create_check_constraint(
                "ck_chat_context_alias_code_format",
                _code_check_expression(),
            )
        return
    if "ck_chat_context_alias_code_length" in checks:
        op.drop_constraint(
            "ck_chat_context_alias_code_length",
            "chat_context_aliases",
            type_="check",
        )
    op.create_check_constraint(
        "ck_chat_context_alias_code_format",
        "chat_context_aliases",
        _code_check_expression(),
    )


def _verify_schema() -> None:
    inspector = inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    missing_tables = sorted(_CONTEXT_TABLES - tables)
    if missing_tables:
        raise RuntimeError(f"chat context tables are missing: {missing_tables}")
    required_context_columns = {
        "id",
        "owner_subject",
        "host_kind",
        "state",
        "project_ref",
        "client_nonce",
        "conversation_ref_hmac",
        "conversation_key_version",
        "generation",
        "created_at",
        "last_seen_at",
        "updated_at",
        "closed_at",
    }
    context_columns = {item["name"] for item in inspector.get_columns("chat_contexts")}
    missing_context_columns = sorted(required_context_columns - context_columns)
    if missing_context_columns:
        raise RuntimeError(
            f"chat context columns are missing: {missing_context_columns}"
        )
    for table_name in _ATTRIBUTION_TABLES:
        columns = {item["name"]: item for item in inspector.get_columns(table_name)}
        column = columns.get("chat_context_id")
        if column is None:
            raise RuntimeError(f"{table_name}.chat_context_id is missing")
        if column["nullable"] is not True:
            raise RuntimeError(f"{table_name}.chat_context_id must remain nullable")
        foreign_keys = inspector.get_foreign_keys(table_name)
        if not any(
            item.get("constrained_columns") == ["chat_context_id"]
            and item.get("referred_table") == "chat_contexts"
            for item in foreign_keys
        ):
            raise RuntimeError(f"{table_name}.chat_context_id foreign key is missing")
    alias_constraints = {
        item.get("name")
        for item in inspector.get_check_constraints("chat_context_aliases")
    }
    if "ck_chat_context_alias_code_format" not in alias_constraints:
        raise RuntimeError("chat context Base62 database constraint is missing")
    alias_unique = {
        item["name"]
        for item in inspector.get_unique_constraints("chat_context_aliases")
        if item.get("name")
    }
    required_alias_unique = {
        "uq_chat_context_alias_owner_code",
        "uq_chat_context_alias_context_generation",
    }
    if not required_alias_unique <= alias_unique:
        raise RuntimeError("chat context historical uniqueness constraints are missing")
    alias_indexes = {
        item["name"] for item in inspector.get_indexes("chat_context_aliases")
    }
    required_alias_indexes = {
        "uq_chat_context_alias_live_code",
        "uq_chat_context_alias_active_context",
    }
    if not required_alias_indexes <= alias_indexes:
        raise RuntimeError("chat context live uniqueness indexes are missing")


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    existing_tables = set(inspector.get_table_names())
    present_context_tables = existing_tables & _CONTEXT_TABLES
    attribution_present = {
        table_name
        for table_name in _ATTRIBUTION_TABLES
        if "chat_context_id"
        in {item["name"] for item in inspector.get_columns(table_name)}
    }
    if present_context_tables and present_context_tables != _CONTEXT_TABLES:
        raise RuntimeError(
            f"partial chat context table schema: {sorted(present_context_tables)}"
        )
    if attribution_present and attribution_present != set(_ATTRIBUTION_TABLES):
        raise RuntimeError(
            f"partial chat context attribution schema: {sorted(attribution_present)}"
        )
    if not present_context_tables:
        _create_context_tables()
    if not attribution_present:
        _add_attribution_columns()
    _ensure_base62_constraint()
    _verify_schema()


def _drop_attribution_columns() -> None:
    dialect = op.get_bind().dialect.name
    for table_name in reversed(_ATTRIBUTION_TABLES):
        if dialect == "postgresql":
            op.drop_constraint(
                _ATTRIBUTION_FKS[table_name],
                table_name,
                type_="foreignkey",
            )
            op.drop_column(table_name, "chat_context_id")
        elif dialect == "sqlite":
            with op.batch_alter_table(table_name, recreate="always") as batch:
                batch.drop_column("chat_context_id")
        else:
            op.drop_column(table_name, "chat_context_id")


def downgrade() -> None:
    _drop_attribution_columns()
    op.drop_table("chat_context_events")
    op.drop_table("chat_context_aliases")
    op.drop_table("chat_contexts")
