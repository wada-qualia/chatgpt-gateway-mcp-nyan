from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "20260725_0003"
down_revision = "20260725_0002"
branch_labels = None
depends_on = None


def _add_columns(table_name: str, columns: dict[str, sa.Column]) -> None:
    connection = op.get_bind()
    inspector = inspect(connection)
    if table_name not in inspector.get_table_names():
        return
    existing = {
        column["name"] for column in inspector.get_columns(table_name)
    }
    for name, column in columns.items():
        if name not in existing:
            op.add_column(table_name, column)


def _create_index(table_name: str, index_name: str, columns: list[str]) -> None:
    connection = op.get_bind()
    inspector = inspect(connection)
    if table_name not in inspector.get_table_names():
        return
    existing = {index["name"] for index in inspector.get_indexes(table_name)}
    if index_name not in existing:
        op.create_index(index_name, table_name, columns)


def _create_ssh_runtime_tables() -> None:
    connection = op.get_bind()
    tables = set(inspect(connection).get_table_names())
    if "ssh_operation_confirmations" not in tables:
        op.create_table(
            "ssh_operation_confirmations",
            sa.Column("id", sa.String(36), nullable=False),
            sa.Column("owner_subject", sa.String(255), nullable=False),
            sa.Column("device_id", sa.String(36), nullable=False),
            sa.Column("command_digest", sa.String(64), nullable=False),
            sa.Column("normalized_command", sa.Text(), nullable=False),
            sa.Column("reasons", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(40), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        for column_name in (
            "owner_subject",
            "device_id",
            "command_digest",
            "status",
            "expires_at",
        ):
            op.create_index(
                f"ix_ssh_operation_confirmations_{column_name}",
                "ssh_operation_confirmations",
                [column_name],
            )
    if "ssh_secure_prompts" not in tables:
        op.create_table(
            "ssh_secure_prompts",
            sa.Column("id", sa.String(36), nullable=False),
            sa.Column("owner_subject", sa.String(255), nullable=False),
            sa.Column("device_id", sa.String(36), nullable=False),
            sa.Column("command_digest", sa.String(64), nullable=False),
            sa.Column("normalized_command", sa.Text(), nullable=False),
            sa.Column("purpose", sa.String(60), nullable=False),
            sa.Column("status", sa.String(40), nullable=False),
            sa.Column("secret_blob_id", sa.String(36), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("ready_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["secret_blob_id"], ["secret_blobs.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        for column_name in (
            "owner_subject",
            "device_id",
            "command_digest",
            "status",
            "expires_at",
        ):
            op.create_index(
                f"ix_ssh_secure_prompts_{column_name}",
                "ssh_secure_prompts",
                [column_name],
            )


def _ensure_postgresql_mcp_revision_guards() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    connection.exec_driver_sql(
        """
        ALTER TABLE mcp_tool_revisions
            ADD COLUMN IF NOT EXISTS search_text TEXT NOT NULL DEFAULT '';
        ALTER TABLE mcp_tool_revisions
            ADD COLUMN IF NOT EXISTS search_vector TSVECTOR
            GENERATED ALWAYS AS (to_tsvector('simple', COALESCE(search_text, ''))) STORED;
        CREATE INDEX IF NOT EXISTS ix_mcp_tool_revision_search_vector
            ON mcp_tool_revisions USING GIN(search_vector);
        """
    )
    connection.exec_driver_sql(
        """
        CREATE OR REPLACE FUNCTION gateway_mcp_tool_revision_guard()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'mcp_tool_revisions are append-only';
            END IF;
            IF NEW.owner_subject IS DISTINCT FROM OLD.owner_subject
               OR NEW.server_id IS DISTINCT FROM OLD.server_id
               OR NEW.tool_id IS DISTINCT FROM OLD.tool_id
               OR NEW.revision_number IS DISTINCT FROM OLD.revision_number
               OR NEW.input_schema IS DISTINCT FROM OLD.input_schema
               OR NEW.output_schema IS DISTINCT FROM OLD.output_schema
               OR NEW.sanitized_title IS DISTINCT FROM OLD.sanitized_title
               OR NEW.sanitized_description IS DISTINCT FROM OLD.sanitized_description
               OR NEW.annotations IS DISTINCT FROM OLD.annotations
               OR NEW.schema_hash IS DISTINCT FROM OLD.schema_hash
               OR NEW.protocol_version IS DISTINCT FROM OLD.protocol_version
               OR NEW.catalog_generation IS DISTINCT FROM OLD.catalog_generation
               OR NEW.discovered_at IS DISTINCT FROM OLD.discovered_at
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'immutable MCP tool revision payload cannot be modified';
            END IF;
            RETURN NEW;
        END;
        $$;
        DROP TRIGGER IF EXISTS trg_mcp_tool_revision_guard ON mcp_tool_revisions;
        CREATE TRIGGER trg_mcp_tool_revision_guard
        BEFORE UPDATE OR DELETE ON mcp_tool_revisions
        FOR EACH ROW
        EXECUTE FUNCTION gateway_mcp_tool_revision_guard();
        """
    )


def upgrade() -> None:
    connection = op.get_bind()
    _create_ssh_runtime_tables()
    _ensure_postgresql_mcp_revision_guards()
    _add_columns(
        "mcp_servers",
        {
            "local_server_id": sa.Column(
                "local_server_id", sa.String(160), nullable=True
            ),
        },
    )
    _add_columns(
        "mcp_invocations",
        {
            "runtime_connection_id": sa.Column(
                "runtime_connection_id", sa.String(36), nullable=True
            ),
            "connection_instance_id": sa.Column(
                "connection_instance_id", sa.String(160), nullable=True
            ),
            "thin_client_request_id": sa.Column(
                "thin_client_request_id", sa.String(160), nullable=True
            ),
        },
    )
    _create_index(
        "mcp_servers",
        "ix_mcp_server_thin_client_runtime",
        ["owner_subject", "thin_client_id", "runtime_id", "status"],
    )
    _create_index(
        "mcp_invocations",
        "ix_mcp_invocation_runtime_connection",
        ["runtime_connection_id", "started_at"],
    )
    _create_index(
        "mcp_invocations",
        "ix_mcp_invocation_connection_instance",
        ["connection_instance_id", "started_at"],
    )
    _create_index(
        "mcp_invocations",
        "ix_mcp_invocation_thin_request",
        ["thin_client_request_id"],
    )
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "uq_mcp_server_thin_runtime_local "
            "ON mcp_servers "
            "(owner_subject, thin_client_id, runtime_id, local_server_id) "
            "WHERE origin = 'thin_client' AND local_server_id IS NOT NULL"
        )
    else:
        existing_indexes = {
            index["name"]
            for index in inspect(connection).get_indexes("mcp_servers")
        }
        if "uq_mcp_server_thin_runtime_local" not in existing_indexes:
            op.create_index(
                "uq_mcp_server_thin_runtime_local",
                "mcp_servers",
                ["owner_subject", "thin_client_id", "runtime_id", "local_server_id"],
                unique=True,
            )
    _add_columns(
        "file_change_sets",
        {
            "room_id": sa.Column("room_id", sa.String(36), nullable=True),
            "agent_id": sa.Column("agent_id", sa.String(36), nullable=True),
            "lease_id": sa.Column("lease_id", sa.String(36), nullable=True),
            "fencing_token": sa.Column("fencing_token", sa.Integer(), nullable=True),
            "before_sha256": sa.Column("before_sha256", sa.String(64), nullable=True),
            "after_sha256": sa.Column("after_sha256", sa.String(64), nullable=True),
            "base_commit": sa.Column("base_commit", sa.String(128), nullable=True),
            "branch_name": sa.Column("branch_name", sa.String(255), nullable=True),
            "worktree_path": sa.Column("worktree_path", sa.Text(), nullable=True),
            "session_id": sa.Column("session_id", sa.String(36), nullable=True),
        },
    )
    for name in ("room_id", "agent_id", "lease_id", "fencing_token"):
        _create_index("file_change_sets", f"ix_file_change_sets_{name}", [name])
    _add_columns(
        "agent_work_items",
        {
            "required_capabilities": sa.Column(
                "required_capabilities", sa.JSON(), nullable=True
            ),
            "assignment_constraints": sa.Column(
                "assignment_constraints", sa.JSON(), nullable=True
            ),
        },
    )
    _add_columns(
        "users",
        {"preferences": sa.Column("preferences", sa.JSON(), nullable=True)},
    )
    _add_columns(
        "secret_blobs",
        {
            "crypto_version": sa.Column(
                "crypto_version",
                sa.String(32),
                nullable=False,
                server_default="fernet-v1",
            ),
            "key_id": sa.Column("key_id", sa.String(64), nullable=True),
        },
    )


def downgrade() -> None:
    pass
