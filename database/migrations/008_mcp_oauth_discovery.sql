CREATE TABLE mcp_oauth_discovery_snapshots (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    resource TEXT NOT NULL,
    resource_metadata_url TEXT NOT NULL,
    authorization_server TEXT NOT NULL,
    authorization_server_metadata_url TEXT NOT NULL,
    discovery_mechanism VARCHAR(60) NOT NULL,
    authorization_endpoint TEXT NOT NULL,
    token_endpoint TEXT NOT NULL,
    registration_endpoint TEXT,
    protected_resource_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    authorization_server_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    requested_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    proposed_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata_hash VARCHAR(64) NOT NULL,
    created_by_subject VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_mcp_oauth_discovery_server_hash UNIQUE (server_id, metadata_hash)
);

CREATE INDEX ix_mcp_oauth_discovery_owner_created ON mcp_oauth_discovery_snapshots (owner_subject, created_at);
CREATE INDEX ix_mcp_oauth_discovery_server_issuer ON mcp_oauth_discovery_snapshots (server_id, authorization_server);
CREATE INDEX ix_mcp_oauth_discovery_server_expires ON mcp_oauth_discovery_snapshots (server_id, expires_at);
CREATE INDEX ix_mcp_oauth_discovery_snapshots_discovery_mechanism ON mcp_oauth_discovery_snapshots (discovery_mechanism);
CREATE INDEX ix_mcp_oauth_discovery_snapshots_metadata_hash ON mcp_oauth_discovery_snapshots (metadata_hash);
CREATE INDEX ix_mcp_oauth_discovery_snapshots_owner_subject ON mcp_oauth_discovery_snapshots (owner_subject);
CREATE INDEX ix_mcp_oauth_discovery_snapshots_server_id ON mcp_oauth_discovery_snapshots (server_id);

CREATE TRIGGER trg_mcp_oauth_discovery_snapshot_append_only
BEFORE UPDATE OR DELETE ON mcp_oauth_discovery_snapshots
FOR EACH ROW EXECUTE FUNCTION gateway_mcp_capability_append_only_guard();
