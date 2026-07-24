from __future__ import annotations

from pathlib import Path

from alembic import op

from gateway_api import models

revision = "20260725_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        snapshot_path = Path(__file__).resolve().parents[1] / "postgresql_baseline.sql"
        for statement in snapshot_path.read_text(encoding="utf-8").split("\n\n"):
            if statement.strip():
                connection.exec_driver_sql(statement)
    else:
        models.Base.metadata.create_all(bind=connection)
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


def downgrade() -> None:
    raise RuntimeError("Gateway baseline downgrade is not supported")
