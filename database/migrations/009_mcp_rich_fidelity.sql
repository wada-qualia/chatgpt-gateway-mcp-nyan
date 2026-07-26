ALTER TABLE mcp_servers
    ADD COLUMN sanitized_instructions TEXT NOT NULL DEFAULT '',
    ADD COLUMN instructions_sha256 VARCHAR(64);

ALTER TABLE mcp_tool_revisions
    ADD COLUMN icons JSON NOT NULL DEFAULT '[]'::json,
    ADD COLUMN execution JSON NOT NULL DEFAULT '{}'::json,
    ADD COLUMN component_meta JSON NOT NULL DEFAULT '{}'::json;

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
       OR NEW.icons::jsonb IS DISTINCT FROM OLD.icons::jsonb
       OR NEW.execution::jsonb IS DISTINCT FROM OLD.execution::jsonb
       OR NEW.component_meta::jsonb IS DISTINCT FROM OLD.component_meta::jsonb
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
