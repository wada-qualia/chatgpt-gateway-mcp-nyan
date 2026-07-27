ALTER TABLE agent_tool_calls
    ADD COLUMN request_characters INTEGER,
    ADD COLUMN response_characters INTEGER,
    ADD COLUMN estimated_input_tokens INTEGER,
    ADD COLUMN estimated_output_tokens INTEGER,
    ADD COLUMN traffic_task_usage_id VARCHAR(36),
    ADD COLUMN traffic_correlation_id VARCHAR(36),
    ADD COLUMN traffic_event_id VARCHAR(36),
    ADD COLUMN traffic_observation_id VARCHAR(36),
    ADD COLUMN traffic_delivery_status VARCHAR(32) NOT NULL DEFAULT 'not_recorded',
    ADD COLUMN traffic_attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN traffic_receipt_status VARCHAR(32),
    ADD COLUMN traffic_last_error_code VARCHAR(128),
    ADD COLUMN traffic_delivered_at TIMESTAMPTZ;

ALTER TABLE agent_tool_calls
    ADD CONSTRAINT ck_agent_tool_calls_traffic_nonnegative
        CHECK (
            (request_characters IS NULL OR request_characters >= 0) AND
            (response_characters IS NULL OR response_characters >= 0) AND
            (estimated_input_tokens IS NULL OR estimated_input_tokens >= 0) AND
            (estimated_output_tokens IS NULL OR estimated_output_tokens >= 0) AND
            traffic_attempt_count >= 0
        ),
    ADD CONSTRAINT ck_agent_tool_calls_traffic_delivery_status
        CHECK (traffic_delivery_status IN ('not_recorded', 'pending', 'delivered', 'disabled'));

CREATE INDEX ix_agent_tool_calls_traffic_delivery_status
    ON agent_tool_calls (traffic_delivery_status);
CREATE UNIQUE INDEX uq_agent_tool_calls_traffic_task_usage_id
    ON agent_tool_calls (traffic_task_usage_id) WHERE traffic_task_usage_id IS NOT NULL;
CREATE UNIQUE INDEX uq_agent_tool_calls_traffic_correlation_id
    ON agent_tool_calls (traffic_correlation_id) WHERE traffic_correlation_id IS NOT NULL;
CREATE UNIQUE INDEX uq_agent_tool_calls_traffic_event_id
    ON agent_tool_calls (traffic_event_id) WHERE traffic_event_id IS NOT NULL;
CREATE UNIQUE INDEX uq_agent_tool_calls_traffic_observation_id
    ON agent_tool_calls (traffic_observation_id) WHERE traffic_observation_id IS NOT NULL;
