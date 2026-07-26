ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS presentation_mode VARCHAR(40) NOT NULL DEFAULT 'native_projected',
    ADD COLUMN IF NOT EXISTS presentation_capabilities JSONB NOT NULL DEFAULT '["native_tools"]'::jsonb,
    ADD COLUMN IF NOT EXISTS workspace_plan VARCHAR(24) NOT NULL DEFAULT 'none';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_oauth_client_presentation_mode'
    ) THEN
        ALTER TABLE oauth_clients
            ADD CONSTRAINT ck_oauth_client_presentation_mode
            CHECK (presentation_mode IN ('catalog_broker', 'deferred_native', 'native_projected'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_oauth_client_workspace_plan'
    ) THEN
        ALTER TABLE oauth_clients
            ADD CONSTRAINT ck_oauth_client_workspace_plan
            CHECK (workspace_plan IN ('none', 'business', 'enterprise', 'edu'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_oauth_clients_presentation_mode
    ON oauth_clients(presentation_mode);
CREATE INDEX IF NOT EXISTS ix_oauth_clients_workspace_plan
    ON oauth_clients(workspace_plan);

ALTER TABLE mcp_projection_verifications
    DROP CONSTRAINT IF EXISTS ck_mcp_projection_verification_kind;
ALTER TABLE mcp_projection_verifications
    ADD CONSTRAINT ck_mcp_projection_verification_kind
    CHECK (verification_kind IN (
        'generic_tools_list_changed',
        'chatgpt_actions',
        'chatgpt_frozen_snapshot',
        'chatgpt_enterprise_refresh',
        'chatgpt_business_republish'
    ));
