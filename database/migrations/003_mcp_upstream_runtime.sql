BEGIN;

CREATE TABLE IF NOT EXISTS mcp_oauth_authorization_states (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    binding_id VARCHAR(36) NOT NULL REFERENCES mcp_credential_bindings(id),
    state_sha256 VARCHAR(64) NOT NULL,
    idempotency_key VARCHAR(160) NOT NULL,
    secret_blob_id VARCHAR(36) NOT NULL REFERENCES secret_blobs(id),
    redirect_uri TEXT NOT NULL,
    authorization_endpoint TEXT NOT NULL,
    token_endpoint TEXT NOT NULL,
    audience TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(40) NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_mcp_oauth_authorization_owner_state UNIQUE(owner_subject, state_sha256),
    CONSTRAINT uq_mcp_oauth_authorization_owner_server_key UNIQUE(owner_subject, server_id, idempotency_key),
    CONSTRAINT ck_mcp_oauth_authorization_status CHECK(status IN ('pending', 'completed', 'expired', 'revoked'))
);

CREATE INDEX IF NOT EXISTS ix_mcp_oauth_authorization_owner_subject
    ON mcp_oauth_authorization_states(owner_subject);
CREATE INDEX IF NOT EXISTS ix_mcp_oauth_authorization_server_id
    ON mcp_oauth_authorization_states(server_id);
CREATE INDEX IF NOT EXISTS ix_mcp_oauth_authorization_binding_id
    ON mcp_oauth_authorization_states(binding_id);
CREATE INDEX IF NOT EXISTS ix_mcp_oauth_authorization_state_sha256
    ON mcp_oauth_authorization_states(state_sha256);
CREATE INDEX IF NOT EXISTS ix_mcp_oauth_authorization_secret_blob_id
    ON mcp_oauth_authorization_states(secret_blob_id);
CREATE INDEX IF NOT EXISTS ix_mcp_oauth_authorization_status
    ON mcp_oauth_authorization_states(status);
CREATE INDEX IF NOT EXISTS ix_mcp_oauth_authorization_expires_at
    ON mcp_oauth_authorization_states(expires_at);
CREATE INDEX IF NOT EXISTS ix_mcp_oauth_authorization_server_expires
    ON mcp_oauth_authorization_states(server_id, expires_at);

COMMIT;
