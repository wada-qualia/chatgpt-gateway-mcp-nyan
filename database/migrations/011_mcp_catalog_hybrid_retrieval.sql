CREATE TABLE mcp_catalog_index_generations (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    scope_server_id VARCHAR(36) REFERENCES mcp_servers(id) ON DELETE CASCADE,
    model_key VARCHAR(120) NOT NULL,
    model_version VARCHAR(120) NOT NULL,
    dimensions INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    status VARCHAR(40) NOT NULL DEFAULT 'building',
    source_catalog_sha256 VARCHAR(64) NOT NULL,
    document_count INTEGER NOT NULL DEFAULT 0,
    supersedes_generation_id VARCHAR(36) REFERENCES mcp_catalog_index_generations(id) ON DELETE SET NULL,
    created_by_subject VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    activated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_mcp_catalog_index_generation_model_generation
        UNIQUE (owner_subject, scope_server_id, model_key, model_version, generation),
    CONSTRAINT ck_mcp_catalog_index_generation_status
        CHECK (status IN ('building', 'ready', 'active', 'retired', 'failed')),
    CONSTRAINT ck_mcp_catalog_index_generation_dimensions
        CHECK (dimensions BETWEEN 1 AND 4096),
    CONSTRAINT ck_mcp_catalog_index_generation_generation
        CHECK (generation > 0),
    CONSTRAINT ck_mcp_catalog_index_generation_document_count
        CHECK (document_count >= 0),
    CONSTRAINT ck_mcp_catalog_index_generation_version
        CHECK (version > 0)
);

CREATE INDEX ix_mcp_catalog_index_generation_owner_status
    ON mcp_catalog_index_generations (owner_subject, status);
CREATE INDEX ix_mcp_catalog_index_generation_model
    ON mcp_catalog_index_generations (owner_subject, model_key, model_version);
CREATE INDEX ix_mcp_catalog_index_generations_owner_subject
    ON mcp_catalog_index_generations (owner_subject);
CREATE INDEX ix_mcp_catalog_index_generations_scope_server_id
    ON mcp_catalog_index_generations (scope_server_id);
CREATE INDEX ix_mcp_catalog_index_generations_status
    ON mcp_catalog_index_generations (status);
CREATE INDEX ix_mcp_catalog_index_generations_supersedes_generation_id
    ON mcp_catalog_index_generations (supersedes_generation_id);
CREATE UNIQUE INDEX uq_mcp_catalog_index_generation_global
    ON mcp_catalog_index_generations (owner_subject, model_key, model_version, generation)
    WHERE scope_server_id IS NULL;
CREATE UNIQUE INDEX uq_mcp_catalog_index_generation_active_owner
    ON mcp_catalog_index_generations (owner_subject)
    WHERE status = 'active';

CREATE TABLE mcp_catalog_embeddings (
    id VARCHAR(36) PRIMARY KEY,
    owner_subject VARCHAR(255) NOT NULL,
    generation_id VARCHAR(36) NOT NULL REFERENCES mcp_catalog_index_generations(id) ON DELETE CASCADE,
    revision_id VARCHAR(36) NOT NULL REFERENCES mcp_tool_revisions(id) ON DELETE CASCADE,
    schema_hash VARCHAR(64) NOT NULL,
    document_sha256 VARCHAR(64) NOT NULL,
    dimensions INTEGER NOT NULL,
    vector JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_mcp_catalog_embedding_generation_revision
        UNIQUE (generation_id, revision_id),
    CONSTRAINT ck_mcp_catalog_embedding_dimensions
        CHECK (dimensions BETWEEN 1 AND 4096),
    CONSTRAINT ck_mcp_catalog_embedding_vector_array
        CHECK (jsonb_typeof(vector) = 'array')
);

CREATE INDEX ix_mcp_catalog_embedding_owner_generation
    ON mcp_catalog_embeddings (owner_subject, generation_id);
CREATE INDEX ix_mcp_catalog_embedding_owner_revision
    ON mcp_catalog_embeddings (owner_subject, revision_id);
CREATE INDEX ix_mcp_catalog_embeddings_owner_subject
    ON mcp_catalog_embeddings (owner_subject);
CREATE INDEX ix_mcp_catalog_embeddings_generation_id
    ON mcp_catalog_embeddings (generation_id);
CREATE INDEX ix_mcp_catalog_embeddings_revision_id
    ON mcp_catalog_embeddings (revision_id);
