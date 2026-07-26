BEGIN;

CREATE TABLE mcp_credential_bindings (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	binding_type VARCHAR(40) NOT NULL,
	provider VARCHAR(120),
	secret_blob_id VARCHAR(36),
	audience VARCHAR(512),
	scopes JSONB NOT NULL,
	status VARCHAR(40) NOT NULL,
	version INTEGER NOT NULL,
	idempotency_key VARCHAR(160),
	meta JSONB NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	rotated_at TIMESTAMP WITH TIME ZONE,
	revoked_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_credential_binding_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	CONSTRAINT ck_mcp_credential_binding_type CHECK (binding_type in ('oauth', 'service_account', 'thin_client_local')),
	FOREIGN KEY(secret_blob_id) REFERENCES secret_blobs (id)
);

CREATE INDEX ix_mcp_credential_binding_owner_status ON mcp_credential_bindings (owner_subject, status);
CREATE INDEX ix_mcp_credential_bindings_binding_type ON mcp_credential_bindings (binding_type);
CREATE INDEX ix_mcp_credential_bindings_owner_subject ON mcp_credential_bindings (owner_subject);
CREATE INDEX ix_mcp_credential_bindings_secret_blob_id ON mcp_credential_bindings (secret_blob_id);
CREATE INDEX ix_mcp_credential_bindings_status ON mcp_credential_bindings (status);

CREATE TABLE mcp_servers (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	origin VARCHAR(40) NOT NULL,
	thin_client_id VARCHAR(36),
	runtime_id VARCHAR(160),
	display_name VARCHAR(180) NOT NULL,
	normalized_slug VARCHAR(120) NOT NULL,
	transport VARCHAR(40) NOT NULL,
	endpoint_url TEXT,
	credential_binding_id VARCHAR(36),
	status VARCHAR(40) NOT NULL,
	trust_level VARCHAR(40) NOT NULL,
	quarantine_reason TEXT,
	negotiated_protocol_version VARCHAR(32),
	capabilities JSONB NOT NULL,
	sanitized_instructions TEXT NOT NULL DEFAULT '',
	instructions_sha256 VARCHAR(64),
	catalog_generation INTEGER NOT NULL,
	policy_generation INTEGER NOT NULL,
	version INTEGER NOT NULL,
	idempotency_key VARCHAR(160),
	last_connected_at TIMESTAMP WITH TIME ZONE,
	last_catalog_refreshed_at TIMESTAMP WITH TIME ZONE,
	disabled_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_server_owner_slug UNIQUE (owner_subject, normalized_slug),
	CONSTRAINT uq_mcp_server_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	CONSTRAINT ck_mcp_server_origin CHECK (origin in ('gateway', 'thin_client')),
	CONSTRAINT ck_mcp_server_transport CHECK (transport in ('streamable_http', 'legacy_sse', 'stdio', 'private_http')),
	CONSTRAINT ck_mcp_server_trust_level CHECK (trust_level in ('unreviewed', 'restricted', 'approved', 'quarantined', 'revoked')),
	FOREIGN KEY(thin_client_id) REFERENCES thin_clients (id),
	FOREIGN KEY(credential_binding_id) REFERENCES mcp_credential_bindings (id)
);

CREATE INDEX ix_mcp_server_owner_status ON mcp_servers (owner_subject, status);
CREATE INDEX ix_mcp_server_owner_trust ON mcp_servers (owner_subject, trust_level);
CREATE INDEX ix_mcp_servers_credential_binding_id ON mcp_servers (credential_binding_id);
CREATE INDEX ix_mcp_servers_origin ON mcp_servers (origin);
CREATE INDEX ix_mcp_servers_owner_subject ON mcp_servers (owner_subject);
CREATE INDEX ix_mcp_servers_runtime_id ON mcp_servers (runtime_id);
CREATE INDEX ix_mcp_servers_status ON mcp_servers (status);
CREATE INDEX ix_mcp_servers_thin_client_id ON mcp_servers (thin_client_id);
CREATE INDEX ix_mcp_servers_transport ON mcp_servers (transport);
CREATE INDEX ix_mcp_servers_trust_level ON mcp_servers (trust_level);

CREATE TABLE mcp_tools (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	server_id VARCHAR(36) NOT NULL,
	upstream_name VARCHAR(255) NOT NULL,
	normalized_name VARCHAR(255) NOT NULL,
	lifecycle_state VARCHAR(40) NOT NULL,
	current_revision_id VARCHAR(36),
	version INTEGER NOT NULL,
	first_observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_tool_server_name UNIQUE (server_id, upstream_name),
	FOREIGN KEY(server_id) REFERENCES mcp_servers (id)
);

CREATE INDEX ix_mcp_tool_owner_state ON mcp_tools (owner_subject, lifecycle_state);
CREATE INDEX ix_mcp_tool_server_current_revision ON mcp_tools (server_id, current_revision_id);
CREATE INDEX ix_mcp_tools_current_revision_id ON mcp_tools (current_revision_id);
CREATE INDEX ix_mcp_tools_lifecycle_state ON mcp_tools (lifecycle_state);
CREATE INDEX ix_mcp_tools_normalized_name ON mcp_tools (normalized_name);
CREATE INDEX ix_mcp_tools_owner_subject ON mcp_tools (owner_subject);
CREATE INDEX ix_mcp_tools_server_id ON mcp_tools (server_id);

CREATE TABLE mcp_tool_revisions (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	server_id VARCHAR(36) NOT NULL,
	tool_id VARCHAR(36) NOT NULL,
	revision_number INTEGER NOT NULL,
	input_schema JSONB NOT NULL,
	output_schema JSONB,
	sanitized_title VARCHAR(240),
	sanitized_description TEXT NOT NULL,
	annotations JSONB NOT NULL,
	icons JSONB NOT NULL DEFAULT '[]'::jsonb,
	execution JSONB NOT NULL DEFAULT '{}'::jsonb,
	component_meta JSONB NOT NULL DEFAULT '{}'::jsonb,
	schema_hash VARCHAR(64) NOT NULL,
	protocol_version VARCHAR(32),
	catalog_generation INTEGER NOT NULL,
	action_class VARCHAR(40) NOT NULL,
	read_only_status VARCHAR(40) NOT NULL,
	risk_evidence JSONB NOT NULL,
	version INTEGER NOT NULL,
	classified_by_subject VARCHAR(255),
	classified_at TIMESTAMP WITH TIME ZONE,
	superseded_by_revision_id VARCHAR(36),
	discovered_at TIMESTAMP WITH TIME ZONE NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_tool_revision_number UNIQUE (tool_id, revision_number),
	CONSTRAINT uq_mcp_tool_revision_schema_hash UNIQUE (tool_id, schema_hash),
	CONSTRAINT ck_mcp_tool_revision_action_class CHECK (action_class in ('unknown', 'read', 'write', 'destructive', 'production')),
	CONSTRAINT ck_mcp_tool_revision_read_only_status CHECK (read_only_status in ('unverified', 'verified', 'rejected')),
	FOREIGN KEY(server_id) REFERENCES mcp_servers (id),
	FOREIGN KEY(tool_id) REFERENCES mcp_tools (id),
	FOREIGN KEY(superseded_by_revision_id) REFERENCES mcp_tool_revisions (id)
);

CREATE INDEX ix_mcp_tool_revision_owner_hash ON mcp_tool_revisions (owner_subject, schema_hash);
CREATE INDEX ix_mcp_tool_revision_server_generation ON mcp_tool_revisions (server_id, catalog_generation);
CREATE INDEX ix_mcp_tool_revisions_action_class ON mcp_tool_revisions (action_class);
CREATE INDEX ix_mcp_tool_revisions_owner_subject ON mcp_tool_revisions (owner_subject);
CREATE INDEX ix_mcp_tool_revisions_read_only_status ON mcp_tool_revisions (read_only_status);
CREATE INDEX ix_mcp_tool_revisions_schema_hash ON mcp_tool_revisions (schema_hash);
CREATE INDEX ix_mcp_tool_revisions_server_id ON mcp_tool_revisions (server_id);
CREATE INDEX ix_mcp_tool_revisions_superseded_by_revision_id ON mcp_tool_revisions (superseded_by_revision_id);
CREATE INDEX ix_mcp_tool_revisions_tool_id ON mcp_tool_revisions (tool_id);

ALTER TABLE mcp_tools
    ADD CONSTRAINT fk_mcp_tools_current_revision
    FOREIGN KEY (current_revision_id) REFERENCES mcp_tool_revisions (id);

CREATE TABLE mcp_tool_exposures (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	server_id VARCHAR(36) NOT NULL,
	tool_id VARCHAR(36) NOT NULL,
	revision_id VARCHAR(36) NOT NULL,
	mode VARCHAR(40) NOT NULL,
	projected_name VARCHAR(255),
	enabled BOOLEAN NOT NULL,
	required_role VARCHAR(120),
	required_scope VARCHAR(160),
	approval_class VARCHAR(40) NOT NULL,
	projection_generation INTEGER NOT NULL,
	policy_generation INTEGER NOT NULL,
	version INTEGER NOT NULL,
	reviewed_by_subject VARCHAR(255),
	reviewed_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_tool_exposure_revision_generation UNIQUE (revision_id, projection_generation),
	CONSTRAINT ck_mcp_tool_exposure_mode CHECK (mode in ('hidden', 'catalog_only', 'native_projected')),
	CONSTRAINT ck_mcp_tool_exposure_approval_class CHECK (approval_class in ('none', 'operator', 'quorum', 'production')),
	FOREIGN KEY(server_id) REFERENCES mcp_servers (id),
	FOREIGN KEY(tool_id) REFERENCES mcp_tools (id),
	FOREIGN KEY(revision_id) REFERENCES mcp_tool_revisions (id)
);

CREATE INDEX ix_mcp_tool_exposure_owner_enabled ON mcp_tool_exposures (owner_subject, enabled);
CREATE INDEX ix_mcp_tool_exposure_tool_mode ON mcp_tool_exposures (tool_id, mode);
CREATE INDEX ix_mcp_tool_exposures_enabled ON mcp_tool_exposures (enabled);
CREATE INDEX ix_mcp_tool_exposures_mode ON mcp_tool_exposures (mode);
CREATE INDEX ix_mcp_tool_exposures_owner_subject ON mcp_tool_exposures (owner_subject);
CREATE INDEX ix_mcp_tool_exposures_projected_name ON mcp_tool_exposures (projected_name);
CREATE INDEX ix_mcp_tool_exposures_revision_id ON mcp_tool_exposures (revision_id);
CREATE INDEX ix_mcp_tool_exposures_server_id ON mcp_tool_exposures (server_id);
CREATE INDEX ix_mcp_tool_exposures_tool_id ON mcp_tool_exposures (tool_id);

CREATE TABLE mcp_federation_policies (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	server_id VARCHAR(36),
	trust_level VARCHAR(40) NOT NULL,
	allowed_action_classes JSONB NOT NULL,
	required_roles JSONB NOT NULL,
	required_scopes JSONB NOT NULL,
	approval_mapping JSONB NOT NULL,
	tool_allowlist JSONB NOT NULL,
	tool_denylist JSONB NOT NULL,
	status VARCHAR(40) NOT NULL,
	generation INTEGER NOT NULL,
	version INTEGER NOT NULL,
	idempotency_key VARCHAR(160),
	created_by_subject VARCHAR(255) NOT NULL,
	updated_by_subject VARCHAR(255) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_federation_policy_owner_server UNIQUE (owner_subject, server_id),
	CONSTRAINT uq_mcp_federation_policy_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	CONSTRAINT ck_mcp_federation_policy_trust_level CHECK (trust_level in ('unreviewed', 'restricted', 'approved', 'quarantined', 'revoked')),
	FOREIGN KEY(server_id) REFERENCES mcp_servers (id)
);

CREATE INDEX ix_mcp_federation_policies_owner_subject ON mcp_federation_policies (owner_subject);
CREATE INDEX ix_mcp_federation_policies_server_id ON mcp_federation_policies (server_id);
CREATE INDEX ix_mcp_federation_policies_status ON mcp_federation_policies (status);
CREATE INDEX ix_mcp_federation_policies_trust_level ON mcp_federation_policies (trust_level);
CREATE INDEX ix_mcp_federation_policy_owner_status ON mcp_federation_policies (owner_subject, status);

CREATE TABLE mcp_runtime_connections (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	server_id VARCHAR(36) NOT NULL,
	thin_client_id VARCHAR(36),
	runtime_id VARCHAR(160),
	connection_instance_id VARCHAR(160) NOT NULL,
	supported_transports JSONB NOT NULL,
	supported_protocol_versions JSONB NOT NULL,
	state VARCHAR(40) NOT NULL,
	acknowledged_catalog_generation INTEGER NOT NULL,
	meta JSONB NOT NULL,
	connected_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
	disconnected_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_runtime_connection_instance UNIQUE (owner_subject, server_id, connection_instance_id),
	FOREIGN KEY(server_id) REFERENCES mcp_servers (id),
	FOREIGN KEY(thin_client_id) REFERENCES thin_clients (id)
);

CREATE INDEX ix_mcp_runtime_connection_owner_seen ON mcp_runtime_connections (owner_subject, last_seen_at);
CREATE INDEX ix_mcp_runtime_connection_server_state ON mcp_runtime_connections (server_id, state);
CREATE INDEX ix_mcp_runtime_connections_connection_instance_id ON mcp_runtime_connections (connection_instance_id);
CREATE INDEX ix_mcp_runtime_connections_owner_subject ON mcp_runtime_connections (owner_subject);
CREATE INDEX ix_mcp_runtime_connections_runtime_id ON mcp_runtime_connections (runtime_id);
CREATE INDEX ix_mcp_runtime_connections_server_id ON mcp_runtime_connections (server_id);
CREATE INDEX ix_mcp_runtime_connections_state ON mcp_runtime_connections (state);
CREATE INDEX ix_mcp_runtime_connections_thin_client_id ON mcp_runtime_connections (thin_client_id);

CREATE TABLE mcp_mutation_receipts (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	operation VARCHAR(120) NOT NULL,
	idempotency_key VARCHAR(160) NOT NULL,
	request_hash VARCHAR(64) NOT NULL,
	resource_type VARCHAR(80) NOT NULL,
	resource_id VARCHAR(36) NOT NULL,
	response_version INTEGER,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_mutation_receipt_owner_operation_key UNIQUE (owner_subject, operation, idempotency_key)
);

CREATE INDEX ix_mcp_mutation_receipt_owner_created ON mcp_mutation_receipts (owner_subject, created_at);
CREATE INDEX ix_mcp_mutation_receipts_created_at ON mcp_mutation_receipts (created_at);
CREATE INDEX ix_mcp_mutation_receipts_operation ON mcp_mutation_receipts (operation);
CREATE INDEX ix_mcp_mutation_receipts_owner_subject ON mcp_mutation_receipts (owner_subject);
CREATE INDEX ix_mcp_mutation_receipts_resource_id ON mcp_mutation_receipts (resource_id);

CREATE TABLE mcp_invocations (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	actor_subject VARCHAR(255) NOT NULL,
	gateway_tool_call_id VARCHAR(36),
	correlation_id VARCHAR(160),
	server_id VARCHAR(36) NOT NULL,
	tool_id VARCHAR(36) NOT NULL,
	revision_id VARCHAR(36) NOT NULL,
	schema_hash VARCHAR(64) NOT NULL,
	action_class VARCHAR(40) NOT NULL,
	arguments_redacted JSONB NOT NULL,
	arguments_sha256 VARCHAR(64) NOT NULL,
	preparation_id VARCHAR(36),
	approval_request_id VARCHAR(36),
	execution_permit_id VARCHAR(36),
	outcome VARCHAR(40) NOT NULL,
	unknown_outcome BOOLEAN NOT NULL,
	normalized_error_code VARCHAR(120),
	normalized_error_detail TEXT,
	response_metadata JSONB NOT NULL,
	response_sha256 VARCHAR(64),
	idempotency_key VARCHAR(160),
	started_at TIMESTAMP WITH TIME ZONE NOT NULL,
	completed_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_invocation_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	CONSTRAINT ck_mcp_invocation_action_class CHECK (action_class in ('unknown', 'read', 'write', 'destructive', 'production')),
	FOREIGN KEY(server_id) REFERENCES mcp_servers (id),
	FOREIGN KEY(tool_id) REFERENCES mcp_tools (id),
	FOREIGN KEY(revision_id) REFERENCES mcp_tool_revisions (id)
);

CREATE INDEX ix_mcp_invocation_outcome_started ON mcp_invocations (outcome, started_at);
CREATE INDEX ix_mcp_invocation_owner_started ON mcp_invocations (owner_subject, started_at);
CREATE INDEX ix_mcp_invocation_server_started ON mcp_invocations (server_id, started_at);
CREATE INDEX ix_mcp_invocations_action_class ON mcp_invocations (action_class);
CREATE INDEX ix_mcp_invocations_actor_subject ON mcp_invocations (actor_subject);
CREATE INDEX ix_mcp_invocations_approval_request_id ON mcp_invocations (approval_request_id);
CREATE INDEX ix_mcp_invocations_correlation_id ON mcp_invocations (correlation_id);
CREATE INDEX ix_mcp_invocations_execution_permit_id ON mcp_invocations (execution_permit_id);
CREATE INDEX ix_mcp_invocations_gateway_tool_call_id ON mcp_invocations (gateway_tool_call_id);
CREATE INDEX ix_mcp_invocations_outcome ON mcp_invocations (outcome);
CREATE INDEX ix_mcp_invocations_owner_subject ON mcp_invocations (owner_subject);
CREATE INDEX ix_mcp_invocations_preparation_id ON mcp_invocations (preparation_id);
CREATE INDEX ix_mcp_invocations_revision_id ON mcp_invocations (revision_id);
CREATE INDEX ix_mcp_invocations_schema_hash ON mcp_invocations (schema_hash);
CREATE INDEX ix_mcp_invocations_server_id ON mcp_invocations (server_id);
CREATE INDEX ix_mcp_invocations_tool_id ON mcp_invocations (tool_id);

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

CREATE TRIGGER trg_mcp_tool_revision_guard
BEFORE UPDATE OR DELETE ON mcp_tool_revisions
FOR EACH ROW
EXECUTE FUNCTION gateway_mcp_tool_revision_guard();

COMMIT;
