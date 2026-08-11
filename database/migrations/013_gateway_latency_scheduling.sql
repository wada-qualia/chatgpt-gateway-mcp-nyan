ALTER TABLE agent_tool_calls
    ADD COLUMN traffic_next_attempt_at TIMESTAMPTZ,
    ADD COLUMN traffic_last_attempt_at TIMESTAMPTZ;

ALTER TABLE agent_tool_calls
    DROP CONSTRAINT IF EXISTS ck_agent_tool_calls_traffic_delivery_status;
ALTER TABLE agent_tool_calls
    ADD CONSTRAINT ck_agent_tool_calls_traffic_delivery_status
    CHECK (
        traffic_delivery_status IN (
            'not_recorded', 'pending', 'delivered', 'disabled', 'dead_letter'
        )
    ) NOT VALID;
ALTER TABLE agent_tool_calls
    VALIDATE CONSTRAINT ck_agent_tool_calls_traffic_delivery_status;

CREATE INDEX CONCURRENTLY ix_outbox_events_ready_claim
    ON outbox_events (available_at, created_at, id)
    WHERE status IN ('pending', 'retry');
CREATE INDEX CONCURRENTLY ix_outbox_events_stale_claim
    ON outbox_events (locked_at, id)
    WHERE status = 'processing' AND locked_at IS NOT NULL;
CREATE INDEX CONCURRENTLY ix_agent_tool_calls_lup_pending_schedule
    ON agent_tool_calls (created_at, id)
    WHERE traffic_delivery_status = 'pending';
