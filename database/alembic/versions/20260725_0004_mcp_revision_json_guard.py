from __future__ import annotations

from alembic import op

revision = "20260725_0004"
down_revision = "20260725_0003"
branch_labels = None
depends_on = None


_GUARD_SQL = """
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
       OR NEW.input_schema::jsonb IS DISTINCT FROM OLD.input_schema::jsonb
       OR NEW.output_schema::jsonb IS DISTINCT FROM OLD.output_schema::jsonb
       OR NEW.sanitized_title IS DISTINCT FROM OLD.sanitized_title
       OR NEW.sanitized_description IS DISTINCT FROM OLD.sanitized_description
       OR NEW.annotations::jsonb IS DISTINCT FROM OLD.annotations::jsonb
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
"""


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    connection.exec_driver_sql(_GUARD_SQL)


def downgrade() -> None:
    raise RuntimeError("MCP revision JSON guard downgrade is not supported")
