BEGIN;

ALTER TABLE mcp_tool_revisions
    ADD COLUMN IF NOT EXISTS search_text TEXT NOT NULL DEFAULT '';

ALTER TABLE mcp_tool_revisions
    ADD COLUMN IF NOT EXISTS search_vector TSVECTOR
    GENERATED ALWAYS AS (to_tsvector('simple', COALESCE(search_text, ''))) STORED;

CREATE INDEX IF NOT EXISTS ix_mcp_tool_revision_search_vector
    ON mcp_tool_revisions USING GIN(search_vector);

CREATE TABLE IF NOT EXISTS mcp_action_preparations (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    actor_subject VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    tool_id VARCHAR(36) NOT NULL REFERENCES mcp_tools(id),
    revision_id VARCHAR(36) NOT NULL REFERENCES mcp_tool_revisions(id),
    schema_hash VARCHAR(64) NOT NULL,
    action_class VARCHAR(40) NOT NULL,
    arguments_secret_id VARCHAR(36) NOT NULL REFERENCES secret_blobs(id),
    arguments_redacted JSONB NOT NULL DEFAULT '{}'::jsonb,
    arguments_sha256 VARCHAR(64) NOT NULL,
    justification TEXT NOT NULL,
    preview JSONB NOT NULL DEFAULT '{}'::jsonb,
    approval_class VARCHAR(40) NOT NULL,
    exposure_id VARCHAR(36) NOT NULL REFERENCES mcp_tool_exposures(id),
    exposure_version INTEGER NOT NULL,
    federation_policy_id VARCHAR(36) NOT NULL REFERENCES mcp_federation_policies(id),
    federation_policy_generation INTEGER NOT NULL,
    autonomy_policy_id VARCHAR(36) NOT NULL,
    autonomy_policy_generation INTEGER NOT NULL,
    command_id VARCHAR(36) NOT NULL,
    executor_agent_id VARCHAR(36) NOT NULL,
    approval_request_id VARCHAR(36) NOT NULL UNIQUE,
    status VARCHAR(40) NOT NULL DEFAULT 'pending_approval',
    idempotency_key VARCHAR(160) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    executed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_mcp_action_preparation_owner_key UNIQUE(owner_subject, idempotency_key),
    CONSTRAINT ck_mcp_action_preparation_action_class CHECK(action_class IN ('write', 'destructive', 'production')),
    CONSTRAINT ck_mcp_action_preparation_status CHECK(status IN ('pending_approval', 'approved', 'executing', 'succeeded', 'failed', 'expired', 'revoked'))
);

CREATE INDEX IF NOT EXISTS ix_mcp_action_preparation_owner_status
    ON mcp_action_preparations(owner_subject, status);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparation_server_created
    ON mcp_action_preparations(server_id, created_at);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_actor_subject
    ON mcp_action_preparations(actor_subject);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_revision_id
    ON mcp_action_preparations(revision_id);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_schema_hash
    ON mcp_action_preparations(schema_hash);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_arguments_secret_id
    ON mcp_action_preparations(arguments_secret_id);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_arguments_sha256
    ON mcp_action_preparations(arguments_sha256);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_exposure_id
    ON mcp_action_preparations(exposure_id);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_federation_policy_id
    ON mcp_action_preparations(federation_policy_id);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_autonomy_policy_id
    ON mcp_action_preparations(autonomy_policy_id);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_command_id
    ON mcp_action_preparations(command_id);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_executor_agent_id
    ON mcp_action_preparations(executor_agent_id);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_expires_at
    ON mcp_action_preparations(expires_at);
CREATE INDEX IF NOT EXISTS ix_mcp_action_preparations_created_at
    ON mcp_action_preparations(created_at);

COMMIT;
