BEGIN;

ALTER TABLE mcp_servers
    ADD COLUMN IF NOT EXISTS local_server_id VARCHAR(160);

CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_server_thin_runtime_local
    ON mcp_servers (owner_subject, thin_client_id, runtime_id, local_server_id)
    WHERE origin = 'thin_client' AND local_server_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_mcp_server_thin_client_runtime
    ON mcp_servers (owner_subject, thin_client_id, runtime_id, status);

ALTER TABLE mcp_invocations
    ADD COLUMN IF NOT EXISTS runtime_connection_id VARCHAR(36),
    ADD COLUMN IF NOT EXISTS connection_instance_id VARCHAR(160),
    ADD COLUMN IF NOT EXISTS thin_client_request_id VARCHAR(160);

CREATE INDEX IF NOT EXISTS ix_mcp_invocation_runtime_connection
    ON mcp_invocations (runtime_connection_id, started_at);
CREATE INDEX IF NOT EXISTS ix_mcp_invocation_connection_instance
    ON mcp_invocations (connection_instance_id, started_at);
CREATE INDEX IF NOT EXISTS ix_mcp_invocation_thin_request
    ON mcp_invocations (thin_client_request_id);

COMMIT;
