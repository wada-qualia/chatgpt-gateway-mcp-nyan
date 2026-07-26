CREATE TABLE mcp_capability_snapshots (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    runtime_connection_id VARCHAR(36) NOT NULL REFERENCES mcp_runtime_connections(id),
    source VARCHAR(60) NOT NULL,
    protocol_version VARCHAR(32) NOT NULL,
    catalog_generation INTEGER NOT NULL DEFAULT 0,
    server_capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
    client_capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
    negotiated_features JSONB NOT NULL DEFAULT '{}'::jsonb,
    capability_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_mcp_capability_snapshot_server_runtime UNIQUE (server_id, runtime_connection_id)
);

CREATE INDEX ix_mcp_capability_snapshot_owner_created ON mcp_capability_snapshots (owner_subject, created_at);
CREATE INDEX ix_mcp_capability_snapshot_server_generation ON mcp_capability_snapshots (server_id, catalog_generation);
CREATE INDEX ix_mcp_capability_snapshots_capability_hash ON mcp_capability_snapshots (capability_hash);
CREATE INDEX ix_mcp_capability_snapshots_protocol_version ON mcp_capability_snapshots (protocol_version);
CREATE INDEX ix_mcp_capability_snapshots_runtime_connection_id ON mcp_capability_snapshots (runtime_connection_id);
CREATE INDEX ix_mcp_capability_snapshots_server_id ON mcp_capability_snapshots (server_id);
CREATE INDEX ix_mcp_capability_snapshots_source ON mcp_capability_snapshots (source);
CREATE INDEX ix_mcp_capability_snapshots_owner_subject ON mcp_capability_snapshots (owner_subject);

CREATE TABLE mcp_capability_entities (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    entity_kind VARCHAR(40) NOT NULL,
    upstream_key TEXT NOT NULL,
    normalized_key VARCHAR(512) NOT NULL,
    lifecycle_state VARCHAR(40) NOT NULL DEFAULT 'active',
    current_revision_id VARCHAR(36),
    version INTEGER NOT NULL DEFAULT 1,
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_mcp_capability_entity_server_kind_key UNIQUE (server_id, entity_kind, upstream_key),
    CONSTRAINT ck_mcp_capability_entity_kind CHECK (entity_kind IN ('resource', 'resource_template', 'prompt')),
    CONSTRAINT ck_mcp_capability_entity_lifecycle CHECK (lifecycle_state IN ('active', 'missing', 'disabled'))
);

CREATE INDEX ix_mcp_capability_entity_owner_kind ON mcp_capability_entities (owner_subject, entity_kind);
CREATE INDEX ix_mcp_capability_entity_server_state ON mcp_capability_entities (server_id, lifecycle_state);
CREATE INDEX ix_mcp_capability_entities_current_revision_id ON mcp_capability_entities (current_revision_id);
CREATE INDEX ix_mcp_capability_entities_entity_kind ON mcp_capability_entities (entity_kind);
CREATE INDEX ix_mcp_capability_entities_lifecycle_state ON mcp_capability_entities (lifecycle_state);
CREATE INDEX ix_mcp_capability_entities_normalized_key ON mcp_capability_entities (normalized_key);
CREATE INDEX ix_mcp_capability_entities_owner_subject ON mcp_capability_entities (owner_subject);
CREATE INDEX ix_mcp_capability_entities_server_id ON mcp_capability_entities (server_id);

CREATE TABLE mcp_capability_entity_revisions (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    entity_id VARCHAR(36) NOT NULL REFERENCES mcp_capability_entities(id),
    entity_kind VARCHAR(40) NOT NULL,
    revision_number INTEGER NOT NULL,
    descriptor JSONB NOT NULL DEFAULT '{}'::jsonb,
    argument_schema JSONB,
    content_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    schema_hash VARCHAR(64) NOT NULL,
    protocol_version VARCHAR(32) NOT NULL,
    catalog_generation INTEGER NOT NULL,
    discovered_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_mcp_capability_entity_revision_number UNIQUE (entity_id, revision_number),
    CONSTRAINT uq_mcp_capability_entity_revision_hash UNIQUE (entity_id, schema_hash),
    CONSTRAINT ck_mcp_capability_entity_revision_kind CHECK (entity_kind IN ('resource', 'resource_template', 'prompt'))
);

ALTER TABLE mcp_capability_entities ADD CONSTRAINT fk_mcp_capability_entity_current_revision FOREIGN KEY (current_revision_id) REFERENCES mcp_capability_entity_revisions(id);

CREATE INDEX ix_mcp_capability_entity_revision_server_generation ON mcp_capability_entity_revisions (server_id, catalog_generation);
CREATE INDEX ix_mcp_capability_entity_revisions_entity_id ON mcp_capability_entity_revisions (entity_id);
CREATE INDEX ix_mcp_capability_entity_revisions_entity_kind ON mcp_capability_entity_revisions (entity_kind);
CREATE INDEX ix_mcp_capability_entity_revisions_owner_subject ON mcp_capability_entity_revisions (owner_subject);
CREATE INDEX ix_mcp_capability_entity_revisions_protocol_version ON mcp_capability_entity_revisions (protocol_version);
CREATE INDEX ix_mcp_capability_entity_revisions_schema_hash ON mcp_capability_entity_revisions (schema_hash);
CREATE INDEX ix_mcp_capability_entity_revisions_server_id ON mcp_capability_entity_revisions (server_id);

CREATE TABLE mcp_capability_subscriptions (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    entity_id VARCHAR(36) REFERENCES mcp_capability_entities(id),
    capability_kind VARCHAR(40) NOT NULL,
    subscription_key VARCHAR(160) NOT NULL,
    uri_sha256 VARCHAR(64) NOT NULL,
    uri_hint VARCHAR(240),
    status VARCHAR(40) NOT NULL DEFAULT 'active',
    list_generation INTEGER NOT NULL DEFAULT 0,
    cursor VARCHAR(512),
    version INTEGER NOT NULL DEFAULT 1,
    last_event_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_mcp_capability_subscription_owner_server_key UNIQUE (owner_subject, server_id, subscription_key),
    CONSTRAINT ck_mcp_capability_subscription_kind CHECK (capability_kind IN ('resource', 'resource_template')),
    CONSTRAINT ck_mcp_capability_subscription_status CHECK (status IN ('active', 'paused', 'revoked'))
);

CREATE INDEX ix_mcp_capability_subscription_server_status ON mcp_capability_subscriptions (server_id, status);
CREATE INDEX ix_mcp_capability_subscriptions_capability_kind ON mcp_capability_subscriptions (capability_kind);
CREATE INDEX ix_mcp_capability_subscriptions_entity_id ON mcp_capability_subscriptions (entity_id);
CREATE INDEX ix_mcp_capability_subscriptions_owner_subject ON mcp_capability_subscriptions (owner_subject);
CREATE INDEX ix_mcp_capability_subscriptions_server_id ON mcp_capability_subscriptions (server_id);
CREATE INDEX ix_mcp_capability_subscriptions_status ON mcp_capability_subscriptions (status);
CREATE INDEX ix_mcp_capability_subscriptions_uri_sha256 ON mcp_capability_subscriptions (uri_sha256);

CREATE TABLE mcp_root_grants (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    runtime_connection_id VARCHAR(36) REFERENCES mcp_runtime_connections(id),
    root_uri_sha256 VARCHAR(64) NOT NULL,
    root_uri_hint VARCHAR(240),
    root_name VARCHAR(240),
    grant_scope VARCHAR(80) NOT NULL DEFAULT 'read',
    status VARCHAR(40) NOT NULL DEFAULT 'pending',
    policy_generation INTEGER NOT NULL DEFAULT 1,
    version INTEGER NOT NULL DEFAULT 1,
    granted_by_subject VARCHAR(255),
    granted_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_mcp_root_grant_owner_server_uri UNIQUE (owner_subject, server_id, root_uri_sha256),
    CONSTRAINT ck_mcp_root_grant_status CHECK (status IN ('pending', 'approved', 'revoked', 'expired'))
);

CREATE INDEX ix_mcp_root_grant_server_status ON mcp_root_grants (server_id, status);
CREATE INDEX ix_mcp_root_grants_owner_subject ON mcp_root_grants (owner_subject);
CREATE INDEX ix_mcp_root_grants_root_uri_sha256 ON mcp_root_grants (root_uri_sha256);
CREATE INDEX ix_mcp_root_grants_runtime_connection_id ON mcp_root_grants (runtime_connection_id);
CREATE INDEX ix_mcp_root_grants_server_id ON mcp_root_grants (server_id);
CREATE INDEX ix_mcp_root_grants_status ON mcp_root_grants (status);

CREATE TABLE mcp_interaction_consents (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    capability VARCHAR(40) NOT NULL,
    request_kind VARCHAR(120) NOT NULL,
    status VARCHAR(40) NOT NULL DEFAULT 'pending',
    required_role VARCHAR(120),
    required_scope VARCHAR(160),
    policy_generation INTEGER NOT NULL DEFAULT 1,
    version INTEGER NOT NULL DEFAULT 1,
    decided_by_subject VARCHAR(255),
    decided_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_mcp_interaction_consent_policy UNIQUE (owner_subject, server_id, capability, request_kind, policy_generation),
    CONSTRAINT ck_mcp_interaction_consent_capability CHECK (capability IN ('sampling', 'elicitation')),
    CONSTRAINT ck_mcp_interaction_consent_status CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'revoked'))
);

CREATE INDEX ix_mcp_interaction_consent_server_status ON mcp_interaction_consents (server_id, status);
CREATE INDEX ix_mcp_interaction_consents_capability ON mcp_interaction_consents (capability);
CREATE INDEX ix_mcp_interaction_consents_owner_subject ON mcp_interaction_consents (owner_subject);
CREATE INDEX ix_mcp_interaction_consents_server_id ON mcp_interaction_consents (server_id);
CREATE INDEX ix_mcp_interaction_consents_status ON mcp_interaction_consents (status);

CREATE TABLE mcp_federated_tasks (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    runtime_connection_id VARCHAR(36) REFERENCES mcp_runtime_connections(id),
    upstream_task_id VARCHAR(255) NOT NULL,
    task_kind VARCHAR(120) NOT NULL,
    request_method VARCHAR(160) NOT NULL,
    status VARCHAR(40) NOT NULL DEFAULT 'working',
    correlation_id VARCHAR(160),
    request_id VARCHAR(160),
    result_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_code VARCHAR(120),
    version INTEGER NOT NULL DEFAULT 1,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_mcp_federated_task_server_upstream UNIQUE (server_id, upstream_task_id),
    CONSTRAINT ck_mcp_federated_task_status CHECK (status IN ('working', 'input_required', 'completed', 'failed', 'cancelled'))
);

CREATE INDEX ix_mcp_federated_task_owner_status ON mcp_federated_tasks (owner_subject, status);
CREATE INDEX ix_mcp_federated_task_server_updated ON mcp_federated_tasks (server_id, updated_at);
CREATE INDEX ix_mcp_federated_tasks_owner_subject ON mcp_federated_tasks (owner_subject);
CREATE INDEX ix_mcp_federated_tasks_runtime_connection_id ON mcp_federated_tasks (runtime_connection_id);
CREATE INDEX ix_mcp_federated_tasks_server_id ON mcp_federated_tasks (server_id);
CREATE INDEX ix_mcp_federated_tasks_status ON mcp_federated_tasks (status);
CREATE INDEX ix_mcp_federated_tasks_task_kind ON mcp_federated_tasks (task_kind);
CREATE INDEX ix_mcp_federated_tasks_upstream_task_id ON mcp_federated_tasks (upstream_task_id);

CREATE TABLE mcp_capability_events (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    server_id VARCHAR(36) NOT NULL REFERENCES mcp_servers(id),
    runtime_connection_id VARCHAR(36) REFERENCES mcp_runtime_connections(id),
    capability VARCHAR(40) NOT NULL,
    event_kind VARCHAR(120) NOT NULL,
    direction VARCHAR(40) NOT NULL,
    correlation_id VARCHAR(160),
    request_id VARCHAR(160),
    task_id VARCHAR(36) REFERENCES mcp_federated_tasks(id),
    entity_id VARCHAR(36) REFERENCES mcp_capability_entities(id),
    payload_redacted JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload_sha256 VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ck_mcp_capability_event_direction CHECK (direction IN ('upstream_to_gateway', 'gateway_to_upstream', 'internal'))
);

CREATE INDEX ix_mcp_capability_event_owner_created ON mcp_capability_events (owner_subject, created_at);
CREATE INDEX ix_mcp_capability_event_server_kind ON mcp_capability_events (server_id, event_kind);
CREATE INDEX ix_mcp_capability_events_capability ON mcp_capability_events (capability);
CREATE INDEX ix_mcp_capability_events_direction ON mcp_capability_events (direction);
CREATE INDEX ix_mcp_capability_events_entity_id ON mcp_capability_events (entity_id);
CREATE INDEX ix_mcp_capability_events_event_kind ON mcp_capability_events (event_kind);
CREATE INDEX ix_mcp_capability_events_owner_subject ON mcp_capability_events (owner_subject);
CREATE INDEX ix_mcp_capability_events_payload_sha256 ON mcp_capability_events (payload_sha256);
CREATE INDEX ix_mcp_capability_events_runtime_connection_id ON mcp_capability_events (runtime_connection_id);
CREATE INDEX ix_mcp_capability_events_server_id ON mcp_capability_events (server_id);
CREATE INDEX ix_mcp_capability_events_task_id ON mcp_capability_events (task_id);

CREATE OR REPLACE FUNCTION gateway_mcp_capability_append_only_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING MESSAGE = TG_TABLE_NAME || ' is append-only';
END;
$$;

CREATE TRIGGER trg_mcp_capability_snapshot_append_only BEFORE UPDATE OR DELETE ON mcp_capability_snapshots FOR EACH ROW EXECUTE FUNCTION gateway_mcp_capability_append_only_guard();
CREATE TRIGGER trg_mcp_capability_entity_revision_append_only BEFORE UPDATE OR DELETE ON mcp_capability_entity_revisions FOR EACH ROW EXECUTE FUNCTION gateway_mcp_capability_append_only_guard();
CREATE TRIGGER trg_mcp_capability_event_append_only BEFORE UPDATE OR DELETE ON mcp_capability_events FOR EACH ROW EXECUTE FUNCTION gateway_mcp_capability_append_only_guard();
