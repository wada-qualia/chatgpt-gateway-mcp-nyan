ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS presentation_profile VARCHAR(40) NOT NULL DEFAULT 'chatgpt-stable',
    ADD COLUMN IF NOT EXISTS presentation_policy_generation INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS allowed_tool_names JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_oauth_client_presentation_profile'
    ) THEN
        ALTER TABLE oauth_clients
            ADD CONSTRAINT ck_oauth_client_presentation_profile
            CHECK (presentation_profile IN ('chatgpt-stable', 'developer-dynamic', 'agent-restricted'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS mcp_projection_generations (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    profile_id VARCHAR(40) NOT NULL,
    generation_number INTEGER NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'candidate',
    previous_generation_id VARCHAR(36) NULL REFERENCES mcp_projection_generations(id),
    content_hash VARCHAR(64) NOT NULL,
    schema_hash VARCHAR(64) NOT NULL,
    change_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    tools_list_changed_state VARCHAR(32) NOT NULL DEFAULT 'not_required',
    chatgpt_refresh_state VARCHAR(32) NOT NULL DEFAULT 'not_required',
    created_by_subject VARCHAR(255) NOT NULL,
    published_by_subject VARCHAR(255) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_mcp_projection_owner_profile_generation
        UNIQUE (owner_subject, profile_id, generation_number),
    CONSTRAINT ck_mcp_projection_profile
        CHECK (profile_id IN ('chatgpt-stable', 'developer-dynamic', 'agent-restricted')),
    CONSTRAINT ck_mcp_projection_status
        CHECK (status IN ('candidate', 'active', 'superseded', 'retired')),
    CONSTRAINT ck_mcp_projection_list_changed_state
        CHECK (tools_list_changed_state IN ('not_required', 'pending', 'notified')),
    CONSTRAINT ck_mcp_projection_chatgpt_refresh_state
        CHECK (chatgpt_refresh_state IN ('not_required', 'pending', 'verified'))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_projection_active_profile
    ON mcp_projection_generations(owner_subject, profile_id)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS ix_mcp_projection_owner_profile_status
    ON mcp_projection_generations(owner_subject, profile_id, status);
CREATE INDEX IF NOT EXISTS ix_mcp_projection_previous
    ON mcp_projection_generations(previous_generation_id);

CREATE TABLE IF NOT EXISTS mcp_projection_tools (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    generation_id VARCHAR(36) NOT NULL REFERENCES mcp_projection_generations(id),
    position INTEGER NOT NULL,
    public_name VARCHAR(255) NOT NULL,
    source_exposure_id VARCHAR(36) NOT NULL REFERENCES mcp_tool_exposures(id),
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    tool_id VARCHAR(36) NOT NULL REFERENCES mcp_tools(id),
    revision_id VARCHAR(36) NOT NULL REFERENCES mcp_tool_revisions(id),
    source_schema_hash VARCHAR(64) NOT NULL,
    input_schema JSONB NOT NULL,
    output_schema JSONB NULL,
    sanitized_title VARCHAR(240) NULL,
    sanitized_description TEXT NOT NULL DEFAULT '',
    annotations JSONB NOT NULL DEFAULT '{}'::jsonb,
    action_class VARCHAR(40) NOT NULL,
    required_role VARCHAR(120) NULL,
    required_scope VARCHAR(160) NULL,
    approval_class VARCHAR(40) NOT NULL DEFAULT 'none',
    change_classification VARCHAR(40) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_mcp_projection_tool_public_name UNIQUE (generation_id, public_name),
    CONSTRAINT uq_mcp_projection_tool_position UNIQUE (generation_id, position),
    CONSTRAINT ck_mcp_projection_tool_action_class
        CHECK (action_class IN ('read', 'write', 'destructive', 'production')),
    CONSTRAINT ck_mcp_projection_tool_change
        CHECK (change_classification IN (
            'new', 'metadata_only', 'backward_compatible_additive',
            'behavior_risk', 'breaking_schema', 'removed_unavailable'
        ))
);

CREATE INDEX IF NOT EXISTS ix_mcp_projection_tool_revision
    ON mcp_projection_tools(revision_id);
CREATE INDEX IF NOT EXISTS ix_mcp_projection_tool_generation_position
    ON mcp_projection_tools(generation_id, position);

CREATE TABLE IF NOT EXISTS mcp_projection_verifications (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    generation_id VARCHAR(36) NOT NULL REFERENCES mcp_projection_generations(id),
    verification_kind VARCHAR(40) NOT NULL,
    observed_schema_hash VARCHAR(64) NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    verified_by_subject VARCHAR(255) NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_mcp_projection_verification_kind
        CHECK (verification_kind IN ('generic_tools_list_changed', 'chatgpt_actions'))
);

CREATE INDEX IF NOT EXISTS ix_mcp_projection_verification_generation
    ON mcp_projection_verifications(generation_id, verification_kind, verified_at DESC);

CREATE OR REPLACE FUNCTION reject_mcp_projection_tool_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'mcp_projection_tools rows are immutable';
END;
$$;

DROP TRIGGER IF EXISTS trg_reject_mcp_projection_tool_update ON mcp_projection_tools;
CREATE TRIGGER trg_reject_mcp_projection_tool_update
BEFORE UPDATE OR DELETE ON mcp_projection_tools
FOR EACH ROW EXECUTE FUNCTION reject_mcp_projection_tool_mutation();

CREATE OR REPLACE FUNCTION protect_mcp_projection_generation_content()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.owner_subject IS DISTINCT FROM OLD.owner_subject
       OR NEW.profile_id IS DISTINCT FROM OLD.profile_id
       OR NEW.generation_number IS DISTINCT FROM OLD.generation_number
       OR NEW.previous_generation_id IS DISTINCT FROM OLD.previous_generation_id
       OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
       OR NEW.schema_hash IS DISTINCT FROM OLD.schema_hash
       OR NEW.change_summary IS DISTINCT FROM OLD.change_summary
       OR NEW.created_by_subject IS DISTINCT FROM OLD.created_by_subject
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'immutable projection generation content cannot be changed';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_mcp_projection_generation_content ON mcp_projection_generations;
CREATE TRIGGER trg_protect_mcp_projection_generation_content
BEFORE UPDATE ON mcp_projection_generations
FOR EACH ROW EXECUTE FUNCTION protect_mcp_projection_generation_content();
