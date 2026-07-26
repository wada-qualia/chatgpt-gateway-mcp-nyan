CREATE TABLE users (
	id SERIAL NOT NULL,
	subject VARCHAR(255) NOT NULL,
	username VARCHAR(120) NOT NULL,
	email VARCHAR(255),
	roles JSON NOT NULL,
	preferences JSON NOT NULL,
	provider VARCHAR(40) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);

CREATE INDEX ix_users_username ON users (username);

CREATE UNIQUE INDEX ix_users_subject ON users (subject);

CREATE TABLE secret_blobs (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	kind VARCHAR(60) NOT NULL,
	ciphertext TEXT NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);

CREATE INDEX ix_secret_blobs_owner_subject ON secret_blobs (owner_subject);

CREATE TABLE docker_workspaces (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	name VARCHAR(160) NOT NULL,
	image VARCHAR(255) NOT NULL,
	container_name VARCHAR(180) NOT NULL,
	container_id VARCHAR(255),
	status VARCHAR(40) NOT NULL,
	source_workspace_id VARCHAR(36),
	meta JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (container_name)
);

CREATE INDEX ix_docker_workspaces_owner_subject ON docker_workspaces (owner_subject);

CREATE TABLE thin_clients (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	hostname VARCHAR(255) NOT NULL,
	directory TEXT NOT NULL,
	agent_token_hash VARCHAR(128) NOT NULL,
	status VARCHAR(40) NOT NULL,
	meta JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);

CREATE INDEX ix_thin_clients_owner_subject ON thin_clients (owner_subject);

CREATE INDEX ix_thin_clients_agent_token_hash ON thin_clients (agent_token_hash);

CREATE TABLE command_sessions (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	origin VARCHAR(40) NOT NULL,
	resource_id VARCHAR(160),
	name VARCHAR(160),
	command TEXT NOT NULL,
	cwd TEXT NOT NULL,
	status VARCHAR(40) NOT NULL,
	pid VARCHAR(80),
	exit_code INTEGER,
	output_path TEXT NOT NULL,
	line_count INTEGER NOT NULL,
	truncated BOOLEAN NOT NULL,
	meta JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	started_at TIMESTAMP WITH TIME ZONE NOT NULL,
	completed_at TIMESTAMP WITH TIME ZONE,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);

CREATE INDEX ix_command_sessions_resource_id ON command_sessions (resource_id);

CREATE INDEX ix_command_sessions_status ON command_sessions (status);

CREATE INDEX ix_command_sessions_owner_subject ON command_sessions (owner_subject);

CREATE INDEX ix_command_sessions_origin ON command_sessions (origin);

CREATE TABLE agent_tool_calls (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	tool_name VARCHAR(120) NOT NULL,
	arguments JSON NOT NULL,
	status VARCHAR(40) NOT NULL,
	session_id VARCHAR(36),
	error TEXT,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	completed_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id)
);

CREATE INDEX ix_agent_tool_calls_tool_name ON agent_tool_calls (tool_name);

CREATE INDEX ix_agent_tool_calls_status ON agent_tool_calls (status);

CREATE INDEX ix_agent_tool_calls_owner_subject ON agent_tool_calls (owner_subject);

CREATE INDEX ix_agent_tool_calls_session_id ON agent_tool_calls (session_id);

CREATE TABLE file_change_sets (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	origin VARCHAR(40) NOT NULL,
	resource_id VARCHAR(160),
	tool_call_id VARCHAR(36),
	room_id VARCHAR(36),
	agent_id VARCHAR(36),
	lease_id VARCHAR(36),
	fencing_token INTEGER,
	path TEXT NOT NULL,
	operation VARCHAR(60) NOT NULL,
	before_sha256 VARCHAR(64),
	after_sha256 VARCHAR(64),
	base_commit VARCHAR(128),
	branch_name VARCHAR(255),
	worktree_path TEXT,
	added_lines INTEGER NOT NULL,
	removed_lines INTEGER NOT NULL,
	bytes_before INTEGER NOT NULL,
	bytes_after INTEGER NOT NULL,
	replacements INTEGER NOT NULL,
	diff_json JSON NOT NULL,
	truncated BOOLEAN NOT NULL,
	suppressed BOOLEAN NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);

CREATE INDEX ix_file_change_sets_lease_id ON file_change_sets (lease_id);

CREATE INDEX ix_file_change_sets_origin ON file_change_sets (origin);

CREATE INDEX ix_file_change_sets_owner_subject ON file_change_sets (owner_subject);

CREATE INDEX ix_file_change_sets_agent_id ON file_change_sets (agent_id);

CREATE INDEX ix_file_change_sets_fencing_token ON file_change_sets (fencing_token);

CREATE INDEX ix_file_change_sets_tool_call_id ON file_change_sets (tool_call_id);

CREATE INDEX ix_file_change_sets_room_id ON file_change_sets (room_id);

CREATE INDEX ix_file_change_sets_operation ON file_change_sets (operation);

CREATE INDEX ix_file_change_sets_resource_id ON file_change_sets (resource_id);

CREATE TABLE oauth_clients (
	client_id VARCHAR(255) NOT NULL,
	client_name VARCHAR(255) NOT NULL,
	redirect_uris JSON NOT NULL,
	scope TEXT NOT NULL,
	presentation_profile VARCHAR(40) NOT NULL,
	presentation_policy_generation INTEGER NOT NULL,
	allowed_tool_names JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (client_id),
	CONSTRAINT ck_oauth_client_presentation_profile CHECK (presentation_profile in ('chatgpt-stable', 'developer-dynamic', 'agent-restricted'))
);

CREATE INDEX ix_oauth_clients_presentation_profile ON oauth_clients (presentation_profile);

CREATE TABLE oauth_codes (
	code VARCHAR(160) NOT NULL,
	client_id VARCHAR(255) NOT NULL,
	redirect_uri TEXT NOT NULL,
	code_challenge VARCHAR(255) NOT NULL,
	scope TEXT NOT NULL,
	subject VARCHAR(255) NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	consumed BOOLEAN NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (code)
);

CREATE INDEX ix_oauth_codes_client_id ON oauth_codes (client_id);

CREATE INDEX ix_oauth_codes_subject ON oauth_codes (subject);

CREATE TABLE device_codes (
	device_code VARCHAR(160) NOT NULL,
	user_code VARCHAR(32) NOT NULL,
	subject VARCHAR(255) NOT NULL,
	scope TEXT NOT NULL,
	status VARCHAR(40) NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (device_code)
);

CREATE INDEX ix_device_codes_subject ON device_codes (subject);

CREATE UNIQUE INDEX ix_device_codes_user_code ON device_codes (user_code);

CREATE TABLE access_grants (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	grantee_subject VARCHAR(255) NOT NULL,
	resource_type VARCHAR(60) NOT NULL,
	resource_id VARCHAR(160) NOT NULL,
	scopes JSON NOT NULL,
	status VARCHAR(40) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);

CREATE INDEX ix_access_grants_owner_subject ON access_grants (owner_subject);

CREATE INDEX ix_access_grants_grantee_subject ON access_grants (grantee_subject);

CREATE TABLE audit_events (
	id VARCHAR(36) NOT NULL,
	event_type VARCHAR(120) NOT NULL,
	actor_subject VARCHAR(255) NOT NULL,
	action VARCHAR(120) NOT NULL,
	resource_type VARCHAR(80) NOT NULL,
	resource_id VARCHAR(160),
	status VARCHAR(40) NOT NULL,
	payload JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);

CREATE INDEX ix_audit_events_actor_subject ON audit_events (actor_subject);

CREATE INDEX ix_audit_events_event_type ON audit_events (event_type);

CREATE TABLE agent_instances (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	logical_agent_id VARCHAR(160) NOT NULL,
	instance_id VARCHAR(160) NOT NULL,
	display_name VARCHAR(160) NOT NULL,
	status VARCHAR(40) NOT NULL,
	capabilities JSON NOT NULL,
	labels JSON NOT NULL,
	current_room_id VARCHAR(36),
	current_work_item_id VARCHAR(36),
	last_heartbeat_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_agent_instance_owner_instance UNIQUE (owner_subject, instance_id)
);

CREATE INDEX ix_agent_instances_owner_subject ON agent_instances (owner_subject);

CREATE INDEX ix_agent_instances_current_work_item_id ON agent_instances (current_work_item_id);

CREATE INDEX ix_agent_instances_status ON agent_instances (status);

CREATE INDEX ix_agent_instances_current_room_id ON agent_instances (current_room_id);

CREATE INDEX ix_agent_instances_logical_agent_id ON agent_instances (logical_agent_id);

CREATE INDEX ix_agent_instances_instance_id ON agent_instances (instance_id);

CREATE INDEX ix_agent_instances_expires_at ON agent_instances (expires_at);

CREATE TABLE collaboration_rooms (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	title VARCHAR(200) NOT NULL,
	project_path TEXT,
	repository_identity VARCHAR(255),
	base_commit VARCHAR(128),
	status VARCHAR(40) NOT NULL,
	policy JSON NOT NULL,
	created_by_agent_id VARCHAR(36),
	idempotency_key VARCHAR(160),
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_collaboration_room_owner_idempotency UNIQUE (owner_subject, idempotency_key)
);

CREATE INDEX ix_collaboration_rooms_created_by_agent_id ON collaboration_rooms (created_by_agent_id);

CREATE INDEX ix_collaboration_rooms_status ON collaboration_rooms (status);

CREATE INDEX ix_collaboration_rooms_repository_identity ON collaboration_rooms (repository_identity);

CREATE INDEX ix_collaboration_rooms_owner_subject ON collaboration_rooms (owner_subject);

CREATE TABLE agent_work_items (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	room_id VARCHAR(36) NOT NULL,
	parent_id VARCHAR(36),
	title VARCHAR(240) NOT NULL,
	description TEXT NOT NULL,
	status VARCHAR(40) NOT NULL,
	priority INTEGER NOT NULL,
	assigned_agent_id VARCHAR(36),
	version INTEGER NOT NULL,
	base_commit VARCHAR(128),
	dependencies JSON NOT NULL,
	acceptance_criteria JSON NOT NULL,
	required_capabilities JSON NOT NULL,
	assignment_constraints JSON NOT NULL,
	result JSON NOT NULL,
	idempotency_key VARCHAR(160),
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_agent_work_item_owner_idempotency UNIQUE (owner_subject, idempotency_key)
);

CREATE INDEX ix_agent_work_items_priority ON agent_work_items (priority);

CREATE INDEX ix_agent_work_items_room_id ON agent_work_items (room_id);

CREATE INDEX ix_agent_work_items_owner_subject ON agent_work_items (owner_subject);

CREATE INDEX ix_agent_work_items_assigned_agent_id ON agent_work_items (assigned_agent_id);

CREATE INDEX ix_agent_work_items_created_at ON agent_work_items (created_at);

CREATE INDEX ix_agent_work_items_parent_id ON agent_work_items (parent_id);

CREATE INDEX ix_agent_work_items_status ON agent_work_items (status);

CREATE TABLE autonomy_control_states (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	scope_type VARCHAR(40) NOT NULL,
	scope_id VARCHAR(160) NOT NULL,
	state VARCHAR(40) NOT NULL,
	generation INTEGER NOT NULL,
	reason TEXT,
	changed_by_subject VARCHAR(255) NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_autonomy_control_scope UNIQUE (owner_subject, scope_type, scope_id)
);

CREATE INDEX ix_autonomy_control_states_state ON autonomy_control_states (state);

CREATE INDEX ix_autonomy_control_states_expires_at ON autonomy_control_states (expires_at);

CREATE INDEX ix_autonomy_control_states_scope_type ON autonomy_control_states (scope_type);

CREATE INDEX ix_autonomy_control_states_scope_id ON autonomy_control_states (scope_id);

CREATE INDEX ix_autonomy_control_states_owner_subject ON autonomy_control_states (owner_subject);

CREATE TABLE autonomy_overrides (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	scope_type VARCHAR(40) NOT NULL,
	scope_id VARCHAR(160) NOT NULL,
	action VARCHAR(60) NOT NULL,
	previous_state VARCHAR(40),
	new_state VARCHAR(40),
	reason TEXT NOT NULL,
	actor_subject VARCHAR(255) NOT NULL,
	evidence JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
);

CREATE INDEX ix_autonomy_overrides_owner_subject ON autonomy_overrides (owner_subject);

CREATE INDEX ix_autonomy_overrides_created_at ON autonomy_overrides (created_at);

CREATE INDEX ix_autonomy_overrides_action ON autonomy_overrides (action);

CREATE INDEX ix_autonomy_overrides_actor_subject ON autonomy_overrides (actor_subject);

CREATE INDEX ix_autonomy_overrides_scope_type ON autonomy_overrides (scope_type);

CREATE INDEX ix_autonomy_overrides_scope_id ON autonomy_overrides (scope_id);

CREATE TABLE processed_broker_messages (
	message_id VARCHAR(160) NOT NULL,
	stream VARCHAR(160),
	consumer VARCHAR(160),
	subject VARCHAR(255) NOT NULL,
	payload_sha256 VARCHAR(64) NOT NULL,
	processed_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (message_id)
);

CREATE INDEX ix_processed_broker_messages_processed_at ON processed_broker_messages (processed_at);

CREATE INDEX ix_processed_broker_messages_consumer ON processed_broker_messages (consumer);

CREATE INDEX ix_processed_broker_messages_subject ON processed_broker_messages (subject);

CREATE INDEX ix_processed_broker_messages_stream ON processed_broker_messages (stream);

CREATE TABLE gateway_replicas (
	id VARCHAR(160) NOT NULL,
	hostname VARCHAR(255) NOT NULL,
	process_id INTEGER NOT NULL,
	status VARCHAR(40) NOT NULL,
	meta JSON NOT NULL,
	started_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_heartbeat_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	stopped_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id)
);

CREATE INDEX ix_gateway_replicas_last_heartbeat_at ON gateway_replicas (last_heartbeat_at);

CREATE INDEX ix_gateway_replicas_expires_at ON gateway_replicas (expires_at);

CREATE INDEX ix_gateway_replicas_status ON gateway_replicas (status);

CREATE TABLE realtime_routes (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	target_kind VARCHAR(40) NOT NULL,
	target_id VARCHAR(160) NOT NULL,
	connection_id VARCHAR(160) NOT NULL,
	replica_id VARCHAR(160) NOT NULL,
	status VARCHAR(40) NOT NULL,
	meta JSON NOT NULL,
	connected_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	disconnected_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_realtime_route_connection UNIQUE (owner_subject, target_kind, target_id, connection_id)
);

CREATE INDEX ix_realtime_routes_target_kind ON realtime_routes (target_kind);

CREATE INDEX ix_realtime_routes_target_id ON realtime_routes (target_id);

CREATE INDEX ix_realtime_routes_expires_at ON realtime_routes (expires_at);

CREATE INDEX ix_realtime_routes_owner_subject ON realtime_routes (owner_subject);

CREATE INDEX ix_realtime_routes_status ON realtime_routes (status);

CREATE INDEX ix_realtime_routes_connection_id ON realtime_routes (connection_id);

CREATE INDEX ix_realtime_routes_replica_id ON realtime_routes (replica_id);

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
	CONSTRAINT uq_mcp_tool_server_name UNIQUE (server_id, upstream_name)
);

CREATE INDEX ix_mcp_tools_normalized_name ON mcp_tools (normalized_name);

CREATE INDEX ix_mcp_tools_current_revision_id ON mcp_tools (current_revision_id);

CREATE INDEX ix_mcp_tool_owner_state ON mcp_tools (owner_subject, lifecycle_state);

CREATE INDEX ix_mcp_tools_server_id ON mcp_tools (server_id);

CREATE INDEX ix_mcp_tools_lifecycle_state ON mcp_tools (lifecycle_state);

CREATE INDEX ix_mcp_tool_server_current_revision ON mcp_tools (server_id, current_revision_id);

CREATE INDEX ix_mcp_tools_owner_subject ON mcp_tools (owner_subject);

CREATE TABLE mcp_tool_revisions (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	server_id VARCHAR(36) NOT NULL,
	tool_id VARCHAR(36) NOT NULL,
	revision_number INTEGER NOT NULL,
	input_schema JSON NOT NULL,
	output_schema JSON,
	sanitized_title VARCHAR(240),
	sanitized_description TEXT NOT NULL,
	search_text TEXT NOT NULL,
	annotations JSON NOT NULL,
	icons JSON NOT NULL,
	execution JSON NOT NULL,
	component_meta JSON NOT NULL,
	schema_hash VARCHAR(64) NOT NULL,
	protocol_version VARCHAR(32),
	catalog_generation INTEGER NOT NULL,
	action_class VARCHAR(40) NOT NULL,
	read_only_status VARCHAR(40) NOT NULL,
	risk_evidence JSON NOT NULL,
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
	CONSTRAINT ck_mcp_tool_revision_read_only_status CHECK (read_only_status in ('unverified', 'verified', 'rejected'))
);

CREATE INDEX ix_mcp_tool_revisions_tool_id ON mcp_tool_revisions (tool_id);

CREATE INDEX ix_mcp_tool_revisions_schema_hash ON mcp_tool_revisions (schema_hash);

CREATE INDEX ix_mcp_tool_revision_server_generation ON mcp_tool_revisions (server_id, catalog_generation);

CREATE INDEX ix_mcp_tool_revisions_action_class ON mcp_tool_revisions (action_class);

CREATE INDEX ix_mcp_tool_revisions_server_id ON mcp_tool_revisions (server_id);

CREATE INDEX ix_mcp_tool_revisions_superseded_by_revision_id ON mcp_tool_revisions (superseded_by_revision_id);

CREATE INDEX ix_mcp_tool_revisions_owner_subject ON mcp_tool_revisions (owner_subject);

CREATE INDEX ix_mcp_tool_revisions_read_only_status ON mcp_tool_revisions (read_only_status);

CREATE INDEX ix_mcp_tool_revision_owner_hash ON mcp_tool_revisions (owner_subject, schema_hash);

CREATE TABLE mcp_projection_generations (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	profile_id VARCHAR(40) NOT NULL,
	generation_number INTEGER NOT NULL,
	status VARCHAR(32) NOT NULL,
	previous_generation_id VARCHAR(36),
	content_hash VARCHAR(64) NOT NULL,
	schema_hash VARCHAR(64) NOT NULL,
	change_summary JSON NOT NULL,
	tools_list_changed_state VARCHAR(32) NOT NULL,
	chatgpt_refresh_state VARCHAR(32) NOT NULL,
	created_by_subject VARCHAR(255) NOT NULL,
	published_by_subject VARCHAR(255),
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	published_at TIMESTAMP WITH TIME ZONE,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_projection_owner_profile_generation UNIQUE (owner_subject, profile_id, generation_number),
	CONSTRAINT ck_mcp_projection_profile CHECK (profile_id in ('chatgpt-stable', 'developer-dynamic', 'agent-restricted')),
	CONSTRAINT ck_mcp_projection_status CHECK (status in ('candidate', 'active', 'superseded', 'retired')),
	CONSTRAINT ck_mcp_projection_list_changed_state CHECK (tools_list_changed_state in ('not_required', 'pending', 'notified')),
	CONSTRAINT ck_mcp_projection_chatgpt_refresh_state CHECK (chatgpt_refresh_state in ('not_required', 'pending', 'verified')),
	FOREIGN KEY(previous_generation_id) REFERENCES mcp_projection_generations (id)
);

CREATE INDEX ix_mcp_projection_owner_profile_status ON mcp_projection_generations (owner_subject, profile_id, status);

CREATE INDEX ix_mcp_projection_generations_owner_subject ON mcp_projection_generations (owner_subject);

CREATE INDEX ix_mcp_projection_generations_content_hash ON mcp_projection_generations (content_hash);

CREATE INDEX ix_mcp_projection_generations_previous_generation_id ON mcp_projection_generations (previous_generation_id);

CREATE INDEX ix_mcp_projection_generations_schema_hash ON mcp_projection_generations (schema_hash);

CREATE INDEX ix_mcp_projection_generations_profile_id ON mcp_projection_generations (profile_id);

CREATE INDEX ix_mcp_projection_generations_status ON mcp_projection_generations (status);

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

CREATE INDEX ix_mcp_mutation_receipts_created_at ON mcp_mutation_receipts (created_at);

CREATE INDEX ix_mcp_mutation_receipts_operation ON mcp_mutation_receipts (operation);

CREATE INDEX ix_mcp_mutation_receipts_resource_id ON mcp_mutation_receipts (resource_id);

CREATE INDEX ix_mcp_mutation_receipt_owner_created ON mcp_mutation_receipts (owner_subject, created_at);

CREATE INDEX ix_mcp_mutation_receipts_owner_subject ON mcp_mutation_receipts (owner_subject);

CREATE TABLE lup_task_starts (
	task_usage_id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	source_message_id VARCHAR(512) NOT NULL,
	session_id VARCHAR(512) NOT NULL,
	trace_id VARCHAR(32),
	correlation_id VARCHAR(36) NOT NULL,
	start_event_id VARCHAR(36) NOT NULL,
	receipt_status VARCHAR(32) NOT NULL,
	receipt_id VARCHAR(36),
	accepted_at TIMESTAMP WITH TIME ZONE,
	broker_provider VARCHAR(128),
	stream_sequence INTEGER,
	receipt_correlation_id VARCHAR(36),
	project_attribution_status VARCHAR(32) NOT NULL,
	project_attribution_source VARCHAR(32) NOT NULL,
	project_atlas_project_key VARCHAR(512),
	project_atlas_entity_id VARCHAR(512),
	project_git_commit VARCHAR(128),
	project_git_branch VARCHAR(255),
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (task_usage_id),
	CONSTRAINT uq_lup_task_starts_owner_message UNIQUE (owner_subject, source_message_id),
	UNIQUE (receipt_id)
);

CREATE INDEX ix_lup_task_starts_session_id ON lup_task_starts (session_id);

CREATE INDEX ix_lup_task_starts_trace_id ON lup_task_starts (trace_id);

CREATE INDEX ix_lup_task_starts_source_message_id ON lup_task_starts (source_message_id);

CREATE UNIQUE INDEX ix_lup_task_starts_start_event_id ON lup_task_starts (start_event_id);

CREATE INDEX ix_lup_task_starts_owner_subject ON lup_task_starts (owner_subject);

CREATE UNIQUE INDEX ix_lup_task_starts_correlation_id ON lup_task_starts (correlation_id);

CREATE TABLE devices (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	name VARCHAR(160) NOT NULL,
	kind VARCHAR(40) NOT NULL,
	host VARCHAR(255) NOT NULL,
	port INTEGER NOT NULL,
	username VARCHAR(120) NOT NULL,
	auth_type VARCHAR(40) NOT NULL,
	credential_secret_id VARCHAR(36),
	status VARCHAR(40) NOT NULL,
	meta JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(credential_secret_id) REFERENCES secret_blobs (id)
);

CREATE INDEX ix_devices_owner_subject ON devices (owner_subject);

CREATE TABLE command_session_deliveries (
	id VARCHAR(36) NOT NULL,
	session_id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	reason VARCHAR(40) NOT NULL,
	start_line INTEGER NOT NULL,
	end_line INTEGER NOT NULL,
	tool_call_id VARCHAR(36),
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(session_id) REFERENCES command_sessions (id)
);

CREATE INDEX ix_command_session_deliveries_session_id ON command_session_deliveries (session_id);

CREATE INDEX ix_command_session_deliveries_tool_call_id ON command_session_deliveries (tool_call_id);

CREATE INDEX ix_command_session_deliveries_owner_subject ON command_session_deliveries (owner_subject);

CREATE INDEX ix_command_session_deliveries_reason ON command_session_deliveries (reason);

CREATE TABLE agent_messages (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	room_id VARCHAR(36) NOT NULL,
	sender_agent_id VARCHAR(36) NOT NULL,
	recipient_agent_id VARCHAR(36),
	recipient_selector VARCHAR(80),
	kind VARCHAR(60) NOT NULL,
	body TEXT NOT NULL,
	payload JSON NOT NULL,
	priority INTEGER NOT NULL,
	correlation_id VARCHAR(160),
	causation_id VARCHAR(160),
	sequence_number INTEGER NOT NULL,
	idempotency_key VARCHAR(160),
	expires_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_agent_message_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	CONSTRAINT uq_agent_message_room_sequence UNIQUE (owner_subject, room_id, sequence_number),
	FOREIGN KEY(room_id) REFERENCES collaboration_rooms (id),
	FOREIGN KEY(sender_agent_id) REFERENCES agent_instances (id),
	FOREIGN KEY(recipient_agent_id) REFERENCES agent_instances (id)
);

CREATE INDEX ix_agent_messages_sender_agent_id ON agent_messages (sender_agent_id);

CREATE INDEX ix_agent_messages_priority ON agent_messages (priority);

CREATE INDEX ix_agent_messages_sequence_number ON agent_messages (sequence_number);

CREATE INDEX ix_agent_messages_owner_subject ON agent_messages (owner_subject);

CREATE INDEX ix_agent_messages_recipient_agent_id ON agent_messages (recipient_agent_id);

CREATE INDEX ix_agent_messages_correlation_id ON agent_messages (correlation_id);

CREATE INDEX ix_agent_messages_created_at ON agent_messages (created_at);

CREATE INDEX ix_agent_messages_kind ON agent_messages (kind);

CREATE INDEX ix_agent_messages_recipient_selector ON agent_messages (recipient_selector);

CREATE INDEX ix_agent_messages_causation_id ON agent_messages (causation_id);

CREATE INDEX ix_agent_messages_room_id ON agent_messages (room_id);

CREATE TABLE agent_commands (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	room_id VARCHAR(36) NOT NULL,
	issuer_agent_id VARCHAR(36) NOT NULL,
	target_agent_id VARCHAR(36) NOT NULL,
	kind VARCHAR(60) NOT NULL,
	instruction TEXT NOT NULL,
	structured_payload JSON NOT NULL,
	constraints JSON NOT NULL,
	priority INTEGER NOT NULL,
	status VARCHAR(40) NOT NULL,
	requires_approval BOOLEAN NOT NULL,
	approved_by_subject VARCHAR(255),
	correlation_id VARCHAR(160),
	causation_id VARCHAR(160),
	idempotency_key VARCHAR(160),
	delivery_attempts INTEGER NOT NULL,
	delivered_at TIMESTAMP WITH TIME ZONE,
	acknowledged_at TIMESTAMP WITH TIME ZONE,
	accepted_at TIMESTAMP WITH TIME ZONE,
	completed_at TIMESTAMP WITH TIME ZONE,
	expires_at TIMESTAMP WITH TIME ZONE,
	result JSON NOT NULL,
	error TEXT,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_agent_command_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	FOREIGN KEY(room_id) REFERENCES collaboration_rooms (id),
	FOREIGN KEY(issuer_agent_id) REFERENCES agent_instances (id),
	FOREIGN KEY(target_agent_id) REFERENCES agent_instances (id)
);

CREATE INDEX ix_agent_commands_issuer_agent_id ON agent_commands (issuer_agent_id);

CREATE INDEX ix_agent_commands_target_agent_id ON agent_commands (target_agent_id);

CREATE INDEX ix_agent_commands_causation_id ON agent_commands (causation_id);

CREATE INDEX ix_agent_commands_room_id ON agent_commands (room_id);

CREATE INDEX ix_agent_commands_priority ON agent_commands (priority);

CREATE INDEX ix_agent_commands_status ON agent_commands (status);

CREATE INDEX ix_agent_commands_created_at ON agent_commands (created_at);

CREATE INDEX ix_agent_commands_owner_subject ON agent_commands (owner_subject);

CREATE INDEX ix_agent_commands_kind ON agent_commands (kind);

CREATE INDEX ix_agent_commands_correlation_id ON agent_commands (correlation_id);

CREATE TABLE resource_leases (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	room_id VARCHAR(36) NOT NULL,
	holder_agent_id VARCHAR(36) NOT NULL,
	work_item_id VARCHAR(36),
	origin VARCHAR(40) NOT NULL,
	resource_id VARCHAR(160),
	mode VARCHAR(40) NOT NULL,
	reservations JSON NOT NULL,
	fencing_token INTEGER NOT NULL,
	status VARCHAR(40) NOT NULL,
	branch_name VARCHAR(255),
	worktree_path TEXT,
	base_commit VARCHAR(128),
	expected_head VARCHAR(128),
	idempotency_key VARCHAR(160),
	meta JSON NOT NULL,
	acquired_at TIMESTAMP WITH TIME ZONE NOT NULL,
	renewed_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	released_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_resource_lease_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	CONSTRAINT uq_resource_lease_room_fence UNIQUE (owner_subject, room_id, fencing_token),
	FOREIGN KEY(room_id) REFERENCES collaboration_rooms (id),
	FOREIGN KEY(holder_agent_id) REFERENCES agent_instances (id),
	FOREIGN KEY(work_item_id) REFERENCES agent_work_items (id)
);

CREATE INDEX ix_resource_leases_owner_subject ON resource_leases (owner_subject);

CREATE INDEX ix_resource_leases_origin ON resource_leases (origin);

CREATE INDEX ix_resource_leases_fencing_token ON resource_leases (fencing_token);

CREATE INDEX ix_resource_leases_expires_at ON resource_leases (expires_at);

CREATE INDEX ix_resource_leases_holder_agent_id ON resource_leases (holder_agent_id);

CREATE INDEX ix_resource_leases_work_item_id ON resource_leases (work_item_id);

CREATE INDEX ix_resource_leases_status ON resource_leases (status);

CREATE INDEX ix_resource_leases_room_id ON resource_leases (room_id);

CREATE INDEX ix_resource_leases_resource_id ON resource_leases (resource_id);

CREATE INDEX ix_resource_leases_mode ON resource_leases (mode);

CREATE INDEX ix_resource_leases_branch_name ON resource_leases (branch_name);

CREATE TABLE agent_integration_records (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	room_id VARCHAR(36) NOT NULL,
	coordinator_agent_id VARCHAR(36) NOT NULL,
	target_branch VARCHAR(255) NOT NULL,
	expected_target_head VARCHAR(128) NOT NULL,
	candidate_change_ids JSON NOT NULL,
	comparison_change_ids JSON NOT NULL,
	source_lease_ids JSON NOT NULL,
	status VARCHAR(40) NOT NULL,
	conflict_report JSON NOT NULL,
	decision JSON NOT NULL,
	integrated_commit VARCHAR(128),
	idempotency_key VARCHAR(160),
	version INTEGER NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	completed_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_agent_integration_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	FOREIGN KEY(room_id) REFERENCES collaboration_rooms (id),
	FOREIGN KEY(coordinator_agent_id) REFERENCES agent_instances (id)
);

CREATE INDEX ix_agent_integration_records_status ON agent_integration_records (status);

CREATE INDEX ix_agent_integration_records_owner_subject ON agent_integration_records (owner_subject);

CREATE INDEX ix_agent_integration_records_room_id ON agent_integration_records (room_id);

CREATE INDEX ix_agent_integration_records_coordinator_agent_id ON agent_integration_records (coordinator_agent_id);

CREATE TABLE autonomy_policies (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	room_id VARCHAR(36) NOT NULL,
	name VARCHAR(200) NOT NULL,
	status VARCHAR(40) NOT NULL,
	assignment_mode VARCHAR(40) NOT NULL,
	coordinator_agent_id VARCHAR(36),
	allowed_action_classes JSON NOT NULL,
	allowed_tools JSON NOT NULL,
	allowed_command_profiles JSON NOT NULL,
	max_parallel_assignments INTEGER NOT NULL,
	approval_rules JSON NOT NULL,
	recovery_policy JSON NOT NULL,
	generation INTEGER NOT NULL,
	version INTEGER NOT NULL,
	idempotency_key VARCHAR(160),
	created_by_subject VARCHAR(255) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_autonomy_policy_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	FOREIGN KEY(room_id) REFERENCES collaboration_rooms (id),
	FOREIGN KEY(coordinator_agent_id) REFERENCES agent_instances (id)
);

CREATE INDEX ix_autonomy_policies_status ON autonomy_policies (status);

CREATE INDEX ix_autonomy_policies_coordinator_agent_id ON autonomy_policies (coordinator_agent_id);

CREATE INDEX ix_autonomy_policies_room_id ON autonomy_policies (room_id);

CREATE INDEX ix_autonomy_policies_assignment_mode ON autonomy_policies (assignment_mode);

CREATE INDEX ix_autonomy_policies_owner_subject ON autonomy_policies (owner_subject);

CREATE TABLE outbox_events (
	id VARCHAR(36) NOT NULL,
	audit_event_id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	event_type VARCHAR(120) NOT NULL,
	subject VARCHAR(255) NOT NULL,
	payload JSON NOT NULL,
	headers JSON NOT NULL,
	status VARCHAR(40) NOT NULL,
	attempt_count INTEGER NOT NULL,
	max_attempts INTEGER NOT NULL,
	available_at TIMESTAMP WITH TIME ZONE NOT NULL,
	locked_by VARCHAR(160),
	lock_token VARCHAR(36),
	locked_at TIMESTAMP WITH TIME ZONE,
	published_at TIMESTAMP WITH TIME ZONE,
	broker_stream VARCHAR(160),
	broker_sequence INTEGER,
	last_error TEXT,
	replay_count INTEGER NOT NULL,
	replayed_from_id VARCHAR(36),
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_outbox_event_audit_event UNIQUE (audit_event_id),
	FOREIGN KEY(audit_event_id) REFERENCES audit_events (id)
);

CREATE UNIQUE INDEX ix_outbox_events_audit_event_id ON outbox_events (audit_event_id);

CREATE INDEX ix_outbox_events_event_type ON outbox_events (event_type);

CREATE INDEX ix_outbox_events_available_at ON outbox_events (available_at);

CREATE INDEX ix_outbox_events_published_at ON outbox_events (published_at);

CREATE INDEX ix_outbox_events_owner_subject ON outbox_events (owner_subject);

CREATE INDEX ix_outbox_events_subject ON outbox_events (subject);

CREATE INDEX ix_outbox_events_locked_by ON outbox_events (locked_by);

CREATE INDEX ix_outbox_events_replayed_from_id ON outbox_events (replayed_from_id);

CREATE INDEX ix_outbox_events_status ON outbox_events (status);

CREATE INDEX ix_outbox_events_lock_token ON outbox_events (lock_token);

CREATE INDEX ix_outbox_events_created_at ON outbox_events (created_at);

CREATE TABLE mcp_credential_bindings (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	binding_type VARCHAR(40) NOT NULL,
	provider VARCHAR(120),
	secret_blob_id VARCHAR(36),
	audience VARCHAR(512),
	scopes JSON NOT NULL,
	status VARCHAR(40) NOT NULL,
	version INTEGER NOT NULL,
	idempotency_key VARCHAR(160),
	meta JSON NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	rotated_at TIMESTAMP WITH TIME ZONE,
	revoked_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_credential_binding_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	CONSTRAINT ck_mcp_credential_binding_type CHECK (binding_type in ('oauth', 'service_account', 'thin_client_local')),
	FOREIGN KEY(secret_blob_id) REFERENCES secret_blobs (id)
);

CREATE INDEX ix_mcp_credential_bindings_secret_blob_id ON mcp_credential_bindings (secret_blob_id);

CREATE INDEX ix_mcp_credential_binding_owner_status ON mcp_credential_bindings (owner_subject, status);

CREATE INDEX ix_mcp_credential_bindings_binding_type ON mcp_credential_bindings (binding_type);

CREATE INDEX ix_mcp_credential_bindings_owner_subject ON mcp_credential_bindings (owner_subject);

CREATE INDEX ix_mcp_credential_bindings_status ON mcp_credential_bindings (status);

CREATE TABLE mcp_projection_verifications (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	generation_id VARCHAR(36) NOT NULL,
	verification_kind VARCHAR(40) NOT NULL,
	observed_schema_hash VARCHAR(64) NOT NULL,
	evidence JSON NOT NULL,
	verified_by_subject VARCHAR(255) NOT NULL,
	verified_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT ck_mcp_projection_verification_kind CHECK (verification_kind in ('generic_tools_list_changed', 'chatgpt_actions')),
	FOREIGN KEY(generation_id) REFERENCES mcp_projection_generations (id)
);

CREATE INDEX ix_mcp_projection_verifications_verification_kind ON mcp_projection_verifications (verification_kind);

CREATE INDEX ix_mcp_projection_verifications_generation_id ON mcp_projection_verifications (generation_id);

CREATE INDEX ix_mcp_projection_verification_generation ON mcp_projection_verifications (generation_id, verification_kind, verified_at);

CREATE INDEX ix_mcp_projection_verifications_owner_subject ON mcp_projection_verifications (owner_subject);

CREATE TABLE lup_tool_calls (
	callback_event_id VARCHAR(36) NOT NULL,
	task_usage_id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	source_message_id VARCHAR(512) NOT NULL,
	session_id VARCHAR(512) NOT NULL,
	callback_id VARCHAR(512) NOT NULL,
	tool_call_id VARCHAR(512) NOT NULL,
	command_session_id VARCHAR(512),
	request_id VARCHAR(512),
	binding_fingerprint VARCHAR(64) NOT NULL,
	usage_measurement JSON,
	observation_event_id VARCHAR(36),
	observation_id VARCHAR(36),
	receipt_status VARCHAR(32),
	receipt_id VARCHAR(36),
	accepted_at TIMESTAMP WITH TIME ZONE,
	broker_provider VARCHAR(128),
	stream_sequence INTEGER,
	receipt_correlation_id VARCHAR(36),
	occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (callback_event_id),
	CONSTRAINT uq_lup_tool_calls_task_callback UNIQUE (task_usage_id, callback_id),
	FOREIGN KEY(task_usage_id) REFERENCES lup_task_starts (task_usage_id),
	UNIQUE (observation_event_id),
	UNIQUE (observation_id),
	UNIQUE (receipt_id)
);

CREATE INDEX ix_lup_tool_calls_owner_subject ON lup_tool_calls (owner_subject);

CREATE INDEX ix_lup_tool_calls_session_id ON lup_tool_calls (session_id);

CREATE INDEX ix_lup_tool_calls_created_at ON lup_tool_calls (created_at);

CREATE INDEX ix_lup_tool_calls_source_message_id ON lup_tool_calls (source_message_id);

CREATE INDEX ix_lup_tool_calls_command_session_id ON lup_tool_calls (command_session_id);

CREATE INDEX ix_lup_tool_calls_task_usage_id ON lup_tool_calls (task_usage_id);

CREATE INDEX ix_lup_tool_calls_tool_call_id ON lup_tool_calls (tool_call_id);

CREATE INDEX ix_lup_tool_calls_request_id ON lup_tool_calls (request_id);

CREATE TABLE lup_tool_phase_seals (
	task_usage_id VARCHAR(36) NOT NULL,
	seal_event_id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	source_message_id VARCHAR(512) NOT NULL,
	session_id VARCHAR(512) NOT NULL,
	last_observation_event_id VARCHAR(36),
	last_observation_id VARCHAR(36),
	receipt_status VARCHAR(32) NOT NULL,
	receipt_id VARCHAR(36),
	accepted_at TIMESTAMP WITH TIME ZONE,
	broker_provider VARCHAR(128),
	stream_sequence INTEGER,
	receipt_correlation_id VARCHAR(36),
	sealed_at TIMESTAMP WITH TIME ZONE NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (task_usage_id),
	FOREIGN KEY(task_usage_id) REFERENCES lup_task_starts (task_usage_id),
	UNIQUE (receipt_id)
);

CREATE INDEX ix_lup_tool_phase_seals_owner_subject ON lup_tool_phase_seals (owner_subject);

CREATE INDEX ix_lup_tool_phase_seals_session_id ON lup_tool_phase_seals (session_id);

CREATE INDEX ix_lup_tool_phase_seals_created_at ON lup_tool_phase_seals (created_at);

CREATE UNIQUE INDEX ix_lup_tool_phase_seals_seal_event_id ON lup_tool_phase_seals (seal_event_id);

CREATE INDEX ix_lup_tool_phase_seals_source_message_id ON lup_tool_phase_seals (source_message_id);

CREATE TABLE lup_task_terminals (
	task_usage_id VARCHAR(36) NOT NULL,
	terminal_event_id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	source_message_id VARCHAR(512) NOT NULL,
	session_id VARCHAR(512) NOT NULL,
	callback_id VARCHAR(512) NOT NULL,
	binding_fingerprint VARCHAR(64) NOT NULL,
	terminal_kind VARCHAR(32) NOT NULL,
	completion_mode VARCHAR(32),
	delivery_state VARCHAR(32),
	recovery_id VARCHAR(512),
	reason_code VARCHAR(64),
	request_id VARCHAR(512),
	final_usage_measurement JSON,
	final_observation_event_id VARCHAR(36),
	final_observation_id VARCHAR(36),
	observation_receipt_status VARCHAR(32),
	observation_receipt_id VARCHAR(36),
	observation_accepted_at TIMESTAMP WITH TIME ZONE,
	observation_broker_provider VARCHAR(128),
	observation_stream_sequence INTEGER,
	observation_receipt_correlation_id VARCHAR(36),
	terminal_receipt_status VARCHAR(32) NOT NULL,
	terminal_receipt_id VARCHAR(36),
	terminal_accepted_at TIMESTAMP WITH TIME ZONE,
	terminal_broker_provider VARCHAR(128),
	terminal_stream_sequence INTEGER,
	terminal_receipt_correlation_id VARCHAR(36),
	terminal_at TIMESTAMP WITH TIME ZONE NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (task_usage_id),
	FOREIGN KEY(task_usage_id) REFERENCES lup_task_starts (task_usage_id),
	UNIQUE (final_observation_event_id),
	UNIQUE (final_observation_id),
	UNIQUE (observation_receipt_id),
	UNIQUE (terminal_receipt_id)
);

CREATE UNIQUE INDEX ix_lup_task_terminals_terminal_event_id ON lup_task_terminals (terminal_event_id);

CREATE INDEX ix_lup_task_terminals_source_message_id ON lup_task_terminals (source_message_id);

CREATE INDEX ix_lup_task_terminals_owner_subject ON lup_task_terminals (owner_subject);

CREATE INDEX ix_lup_task_terminals_request_id ON lup_task_terminals (request_id);

CREATE INDEX ix_lup_task_terminals_created_at ON lup_task_terminals (created_at);

CREATE INDEX ix_lup_task_terminals_session_id ON lup_task_terminals (session_id);

CREATE INDEX ix_lup_task_terminals_terminal_kind ON lup_task_terminals (terminal_kind);

CREATE TABLE agent_message_deliveries (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	message_id VARCHAR(36) NOT NULL,
	recipient_agent_id VARCHAR(36) NOT NULL,
	status VARCHAR(40) NOT NULL,
	attempt_count INTEGER NOT NULL,
	delivered_at TIMESTAMP WITH TIME ZONE,
	acknowledged_at TIMESTAMP WITH TIME ZONE,
	visibility_deadline TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_agent_message_delivery_recipient UNIQUE (message_id, recipient_agent_id),
	FOREIGN KEY(message_id) REFERENCES agent_messages (id),
	FOREIGN KEY(recipient_agent_id) REFERENCES agent_instances (id)
);

CREATE INDEX ix_agent_message_deliveries_message_id ON agent_message_deliveries (message_id);

CREATE INDEX ix_agent_message_deliveries_created_at ON agent_message_deliveries (created_at);

CREATE INDEX ix_agent_message_deliveries_owner_subject ON agent_message_deliveries (owner_subject);

CREATE INDEX ix_agent_message_deliveries_recipient_agent_id ON agent_message_deliveries (recipient_agent_id);

CREATE INDEX ix_agent_message_deliveries_status ON agent_message_deliveries (status);

CREATE TABLE agent_handoff_barriers (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	room_id VARCHAR(36) NOT NULL,
	source_agent_id VARCHAR(36) NOT NULL,
	target_agent_id VARCHAR(36) NOT NULL,
	lease_id VARCHAR(36) NOT NULL,
	expected_fencing_token INTEGER NOT NULL,
	required_change_ids JSON NOT NULL,
	summary TEXT NOT NULL,
	payload JSON NOT NULL,
	status VARCHAR(40) NOT NULL,
	conflict_report JSON NOT NULL,
	idempotency_key VARCHAR(160),
	ready_at TIMESTAMP WITH TIME ZONE,
	accepted_at TIMESTAMP WITH TIME ZONE,
	cancelled_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_agent_handoff_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	FOREIGN KEY(room_id) REFERENCES collaboration_rooms (id),
	FOREIGN KEY(source_agent_id) REFERENCES agent_instances (id),
	FOREIGN KEY(target_agent_id) REFERENCES agent_instances (id),
	FOREIGN KEY(lease_id) REFERENCES resource_leases (id)
);

CREATE INDEX ix_agent_handoff_barriers_owner_subject ON agent_handoff_barriers (owner_subject);

CREATE INDEX ix_agent_handoff_barriers_room_id ON agent_handoff_barriers (room_id);

CREATE INDEX ix_agent_handoff_barriers_lease_id ON agent_handoff_barriers (lease_id);

CREATE INDEX ix_agent_handoff_barriers_source_agent_id ON agent_handoff_barriers (source_agent_id);

CREATE INDEX ix_agent_handoff_barriers_status ON agent_handoff_barriers (status);

CREATE INDEX ix_agent_handoff_barriers_target_agent_id ON agent_handoff_barriers (target_agent_id);

CREATE TABLE autonomy_assignments (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	room_id VARCHAR(36) NOT NULL,
	policy_id VARCHAR(36) NOT NULL,
	work_item_id VARCHAR(36) NOT NULL,
	selected_agent_id VARCHAR(36) NOT NULL,
	status VARCHAR(40) NOT NULL,
	score INTEGER NOT NULL,
	rationale JSON NOT NULL,
	policy_generation INTEGER NOT NULL,
	work_item_version INTEGER NOT NULL,
	idempotency_key VARCHAR(160),
	created_by_subject VARCHAR(255) NOT NULL,
	applied_at TIMESTAMP WITH TIME ZONE,
	revoked_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_autonomy_assignment_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	FOREIGN KEY(room_id) REFERENCES collaboration_rooms (id),
	FOREIGN KEY(policy_id) REFERENCES autonomy_policies (id),
	FOREIGN KEY(work_item_id) REFERENCES agent_work_items (id),
	FOREIGN KEY(selected_agent_id) REFERENCES agent_instances (id)
);

CREATE INDEX ix_autonomy_assignments_owner_subject ON autonomy_assignments (owner_subject);

CREATE INDEX ix_autonomy_assignments_work_item_id ON autonomy_assignments (work_item_id);

CREATE INDEX ix_autonomy_assignments_created_at ON autonomy_assignments (created_at);

CREATE INDEX ix_autonomy_assignments_selected_agent_id ON autonomy_assignments (selected_agent_id);

CREATE INDEX ix_autonomy_assignments_room_id ON autonomy_assignments (room_id);

CREATE INDEX ix_autonomy_assignments_policy_id ON autonomy_assignments (policy_id);

CREATE INDEX ix_autonomy_assignments_status ON autonomy_assignments (status);

CREATE TABLE approval_requests (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	room_id VARCHAR(36) NOT NULL,
	policy_id VARCHAR(36) NOT NULL,
	command_id VARCHAR(36),
	work_item_id VARCHAR(36),
	integration_id VARCHAR(36),
	proposer_agent_id VARCHAR(36),
	executor_agent_id VARCHAR(36) NOT NULL,
	action_kind VARCHAR(120) NOT NULL,
	action_class VARCHAR(40) NOT NULL,
	tool VARCHAR(160) NOT NULL,
	command_profile VARCHAR(160),
	payload_hash VARCHAR(64) NOT NULL,
	payload_summary JSON NOT NULL,
	quorum_required INTEGER NOT NULL,
	require_admin_approval BOOLEAN NOT NULL,
	disallow_proposer_vote BOOLEAN NOT NULL,
	status VARCHAR(40) NOT NULL,
	policy_generation INTEGER NOT NULL,
	version INTEGER NOT NULL,
	idempotency_key VARCHAR(160),
	created_by_subject VARCHAR(255) NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	approved_at TIMESTAMP WITH TIME ZONE,
	rejected_at TIMESTAMP WITH TIME ZONE,
	revoked_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_approval_request_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	FOREIGN KEY(room_id) REFERENCES collaboration_rooms (id),
	FOREIGN KEY(policy_id) REFERENCES autonomy_policies (id),
	FOREIGN KEY(command_id) REFERENCES agent_commands (id),
	FOREIGN KEY(work_item_id) REFERENCES agent_work_items (id),
	FOREIGN KEY(integration_id) REFERENCES agent_integration_records (id),
	FOREIGN KEY(proposer_agent_id) REFERENCES agent_instances (id),
	FOREIGN KEY(executor_agent_id) REFERENCES agent_instances (id)
);

CREATE INDEX ix_approval_requests_work_item_id ON approval_requests (work_item_id);

CREATE INDEX ix_approval_requests_proposer_agent_id ON approval_requests (proposer_agent_id);

CREATE INDEX ix_approval_requests_tool ON approval_requests (tool);

CREATE INDEX ix_approval_requests_status ON approval_requests (status);

CREATE INDEX ix_approval_requests_expires_at ON approval_requests (expires_at);

CREATE INDEX ix_approval_requests_policy_id ON approval_requests (policy_id);

CREATE INDEX ix_approval_requests_command_id ON approval_requests (command_id);

CREATE INDEX ix_approval_requests_executor_agent_id ON approval_requests (executor_agent_id);

CREATE INDEX ix_approval_requests_command_profile ON approval_requests (command_profile);

CREATE INDEX ix_approval_requests_created_by_subject ON approval_requests (created_by_subject);

CREATE INDEX ix_approval_requests_created_at ON approval_requests (created_at);

CREATE INDEX ix_approval_requests_room_id ON approval_requests (room_id);

CREATE INDEX ix_approval_requests_action_class ON approval_requests (action_class);

CREATE INDEX ix_approval_requests_integration_id ON approval_requests (integration_id);

CREATE INDEX ix_approval_requests_action_kind ON approval_requests (action_kind);

CREATE INDEX ix_approval_requests_payload_hash ON approval_requests (payload_hash);

CREATE INDEX ix_approval_requests_owner_subject ON approval_requests (owner_subject);

CREATE TABLE recovery_loops (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	room_id VARCHAR(36) NOT NULL,
	policy_id VARCHAR(36) NOT NULL,
	source_type VARCHAR(40) NOT NULL,
	source_id VARCHAR(160) NOT NULL,
	target_agent_id VARCHAR(36) NOT NULL,
	strategy JSON NOT NULL,
	status VARCHAR(40) NOT NULL,
	attempt_count INTEGER NOT NULL,
	max_attempts INTEGER NOT NULL,
	base_backoff_seconds INTEGER NOT NULL,
	next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_command_id VARCHAR(36),
	last_error TEXT,
	policy_generation INTEGER NOT NULL,
	generation INTEGER NOT NULL,
	idempotency_key VARCHAR(160),
	created_by_subject VARCHAR(255) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	completed_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_recovery_loop_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	FOREIGN KEY(room_id) REFERENCES collaboration_rooms (id),
	FOREIGN KEY(policy_id) REFERENCES autonomy_policies (id),
	FOREIGN KEY(target_agent_id) REFERENCES agent_instances (id),
	FOREIGN KEY(last_command_id) REFERENCES agent_commands (id)
);

CREATE INDEX ix_recovery_loops_room_id ON recovery_loops (room_id);

CREATE INDEX ix_recovery_loops_target_agent_id ON recovery_loops (target_agent_id);

CREATE INDEX ix_recovery_loops_last_command_id ON recovery_loops (last_command_id);

CREATE INDEX ix_recovery_loops_owner_subject ON recovery_loops (owner_subject);

CREATE INDEX ix_recovery_loops_source_type ON recovery_loops (source_type);

CREATE INDEX ix_recovery_loops_next_attempt_at ON recovery_loops (next_attempt_at);

CREATE INDEX ix_recovery_loops_source_id ON recovery_loops (source_id);

CREATE INDEX ix_recovery_loops_policy_id ON recovery_loops (policy_id);

CREATE INDEX ix_recovery_loops_status ON recovery_loops (status);

CREATE INDEX ix_recovery_loops_created_at ON recovery_loops (created_at);

CREATE TABLE outbox_delivery_attempts (
	id VARCHAR(36) NOT NULL,
	outbox_event_id VARCHAR(36) NOT NULL,
	attempt_number INTEGER NOT NULL,
	replica_id VARCHAR(160) NOT NULL,
	status VARCHAR(40) NOT NULL,
	error TEXT,
	broker_stream VARCHAR(160),
	broker_sequence INTEGER,
	started_at TIMESTAMP WITH TIME ZONE NOT NULL,
	completed_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_outbox_attempt_number UNIQUE (outbox_event_id, attempt_number),
	FOREIGN KEY(outbox_event_id) REFERENCES outbox_events (id)
);

CREATE INDEX ix_outbox_delivery_attempts_outbox_event_id ON outbox_delivery_attempts (outbox_event_id);

CREATE INDEX ix_outbox_delivery_attempts_status ON outbox_delivery_attempts (status);

CREATE INDEX ix_outbox_delivery_attempts_replica_id ON outbox_delivery_attempts (replica_id);

CREATE TABLE realtime_notifications (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	target_kind VARCHAR(40) NOT NULL,
	target_id VARCHAR(160) NOT NULL,
	event_type VARCHAR(120) NOT NULL,
	payload JSON NOT NULL,
	status VARCHAR(40) NOT NULL,
	replica_id VARCHAR(160),
	outbox_event_id VARCHAR(36),
	attempt_count INTEGER NOT NULL,
	delivered_at TIMESTAMP WITH TIME ZONE,
	acknowledged_at TIMESTAMP WITH TIME ZONE,
	expires_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(outbox_event_id) REFERENCES outbox_events (id)
);

CREATE INDEX ix_realtime_notifications_event_type ON realtime_notifications (event_type);

CREATE INDEX ix_realtime_notifications_status ON realtime_notifications (status);

CREATE INDEX ix_realtime_notifications_expires_at ON realtime_notifications (expires_at);

CREATE INDEX ix_realtime_notifications_target_kind ON realtime_notifications (target_kind);

CREATE INDEX ix_realtime_notifications_target_id ON realtime_notifications (target_id);

CREATE INDEX ix_realtime_notifications_outbox_event_id ON realtime_notifications (outbox_event_id);

CREATE INDEX ix_realtime_notifications_owner_subject ON realtime_notifications (owner_subject);

CREATE INDEX ix_realtime_notifications_replica_id ON realtime_notifications (replica_id);

CREATE INDEX ix_realtime_notifications_created_at ON realtime_notifications (created_at);

CREATE TABLE mcp_servers (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	origin VARCHAR(40) NOT NULL,
	thin_client_id VARCHAR(36),
	runtime_id VARCHAR(160),
	local_server_id VARCHAR(160),
	display_name VARCHAR(180) NOT NULL,
	normalized_slug VARCHAR(120) NOT NULL,
	transport VARCHAR(40) NOT NULL,
	endpoint_url TEXT,
	credential_binding_id VARCHAR(36),
	status VARCHAR(40) NOT NULL,
	trust_level VARCHAR(40) NOT NULL,
	quarantine_reason TEXT,
	negotiated_protocol_version VARCHAR(32),
	capabilities JSON NOT NULL,
	sanitized_instructions TEXT NOT NULL,
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

CREATE INDEX ix_mcp_servers_thin_client_id ON mcp_servers (thin_client_id);

CREATE INDEX ix_mcp_servers_credential_binding_id ON mcp_servers (credential_binding_id);

CREATE INDEX ix_mcp_server_owner_trust ON mcp_servers (owner_subject, trust_level);

CREATE INDEX ix_mcp_servers_owner_subject ON mcp_servers (owner_subject);

CREATE INDEX ix_mcp_servers_transport ON mcp_servers (transport);

CREATE INDEX ix_mcp_servers_trust_level ON mcp_servers (trust_level);

CREATE INDEX ix_mcp_server_owner_status ON mcp_servers (owner_subject, status);

CREATE INDEX ix_mcp_servers_local_server_id ON mcp_servers (local_server_id);

CREATE INDEX ix_mcp_servers_runtime_id ON mcp_servers (runtime_id);

CREATE INDEX ix_mcp_servers_status ON mcp_servers (status);

CREATE INDEX ix_mcp_servers_origin ON mcp_servers (origin);

CREATE TABLE approval_votes (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	request_id VARCHAR(36) NOT NULL,
	voter_subject VARCHAR(255) NOT NULL,
	voter_roles JSON NOT NULL,
	decision VARCHAR(40) NOT NULL,
	reason TEXT,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_approval_vote_subject UNIQUE (request_id, voter_subject),
	FOREIGN KEY(request_id) REFERENCES approval_requests (id)
);

CREATE INDEX ix_approval_votes_voter_subject ON approval_votes (voter_subject);

CREATE INDEX ix_approval_votes_created_at ON approval_votes (created_at);

CREATE INDEX ix_approval_votes_request_id ON approval_votes (request_id);

CREATE INDEX ix_approval_votes_decision ON approval_votes (decision);

CREATE INDEX ix_approval_votes_owner_subject ON approval_votes (owner_subject);

CREATE TABLE execution_permits (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	approval_request_id VARCHAR(36) NOT NULL,
	policy_id VARCHAR(36) NOT NULL,
	command_id VARCHAR(36),
	executor_agent_id VARCHAR(36) NOT NULL,
	action_class VARCHAR(40) NOT NULL,
	tool VARCHAR(160) NOT NULL,
	command_profile VARCHAR(160),
	payload_hash VARCHAR(64) NOT NULL,
	status VARCHAR(40) NOT NULL,
	policy_generation INTEGER NOT NULL,
	control_snapshot JSON NOT NULL,
	fencing_token INTEGER NOT NULL,
	max_uses INTEGER NOT NULL,
	use_count INTEGER NOT NULL,
	issued_by_subject VARCHAR(255) NOT NULL,
	issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	claimed_at TIMESTAMP WITH TIME ZONE,
	consumed_at TIMESTAMP WITH TIME ZONE,
	revoked_at TIMESTAMP WITH TIME ZONE,
	revocation_reason TEXT,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_execution_permit_request UNIQUE (approval_request_id),
	FOREIGN KEY(approval_request_id) REFERENCES approval_requests (id),
	FOREIGN KEY(policy_id) REFERENCES autonomy_policies (id),
	FOREIGN KEY(command_id) REFERENCES agent_commands (id),
	FOREIGN KEY(executor_agent_id) REFERENCES agent_instances (id)
);

CREATE UNIQUE INDEX ix_execution_permits_approval_request_id ON execution_permits (approval_request_id);

CREATE INDEX ix_execution_permits_tool ON execution_permits (tool);

CREATE INDEX ix_execution_permits_action_class ON execution_permits (action_class);

CREATE INDEX ix_execution_permits_status ON execution_permits (status);

CREATE INDEX ix_execution_permits_owner_subject ON execution_permits (owner_subject);

CREATE INDEX ix_execution_permits_executor_agent_id ON execution_permits (executor_agent_id);

CREATE INDEX ix_execution_permits_command_profile ON execution_permits (command_profile);

CREATE INDEX ix_execution_permits_expires_at ON execution_permits (expires_at);

CREATE INDEX ix_execution_permits_policy_id ON execution_permits (policy_id);

CREATE INDEX ix_execution_permits_command_id ON execution_permits (command_id);

CREATE INDEX ix_execution_permits_payload_hash ON execution_permits (payload_hash);

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

CREATE INDEX ix_mcp_tool_exposures_enabled ON mcp_tool_exposures (enabled);

CREATE INDEX ix_mcp_tool_exposure_owner_enabled ON mcp_tool_exposures (owner_subject, enabled);

CREATE INDEX ix_mcp_tool_exposures_owner_subject ON mcp_tool_exposures (owner_subject);

CREATE INDEX ix_mcp_tool_exposures_mode ON mcp_tool_exposures (mode);

CREATE INDEX ix_mcp_tool_exposure_tool_mode ON mcp_tool_exposures (tool_id, mode);

CREATE INDEX ix_mcp_tool_exposures_tool_id ON mcp_tool_exposures (tool_id);

CREATE INDEX ix_mcp_tool_exposures_revision_id ON mcp_tool_exposures (revision_id);

CREATE INDEX ix_mcp_tool_exposures_server_id ON mcp_tool_exposures (server_id);

CREATE INDEX ix_mcp_tool_exposures_projected_name ON mcp_tool_exposures (projected_name);

CREATE TABLE mcp_federation_policies (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	server_id VARCHAR(36),
	trust_level VARCHAR(40) NOT NULL,
	allowed_action_classes JSON NOT NULL,
	required_roles JSON NOT NULL,
	required_scopes JSON NOT NULL,
	approval_mapping JSON NOT NULL,
	tool_allowlist JSON NOT NULL,
	tool_denylist JSON NOT NULL,
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

CREATE INDEX ix_mcp_federation_policies_trust_level ON mcp_federation_policies (trust_level);

CREATE INDEX ix_mcp_federation_policies_server_id ON mcp_federation_policies (server_id);

CREATE INDEX ix_mcp_federation_policies_status ON mcp_federation_policies (status);

CREATE INDEX ix_mcp_federation_policy_owner_status ON mcp_federation_policies (owner_subject, status);

CREATE INDEX ix_mcp_federation_policies_owner_subject ON mcp_federation_policies (owner_subject);

CREATE TABLE mcp_runtime_connections (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	server_id VARCHAR(36) NOT NULL,
	thin_client_id VARCHAR(36),
	runtime_id VARCHAR(160),
	connection_instance_id VARCHAR(160) NOT NULL,
	supported_transports JSON NOT NULL,
	supported_protocol_versions JSON NOT NULL,
	state VARCHAR(40) NOT NULL,
	acknowledged_catalog_generation INTEGER NOT NULL,
	meta JSON NOT NULL,
	connected_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
	disconnected_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_runtime_connection_instance UNIQUE (owner_subject, server_id, connection_instance_id),
	FOREIGN KEY(server_id) REFERENCES mcp_servers (id),
	FOREIGN KEY(thin_client_id) REFERENCES thin_clients (id)
);

CREATE INDEX ix_mcp_runtime_connections_runtime_id ON mcp_runtime_connections (runtime_id);

CREATE INDEX ix_mcp_runtime_connection_server_state ON mcp_runtime_connections (server_id, state);

CREATE INDEX ix_mcp_runtime_connections_connection_instance_id ON mcp_runtime_connections (connection_instance_id);

CREATE INDEX ix_mcp_runtime_connections_thin_client_id ON mcp_runtime_connections (thin_client_id);

CREATE INDEX ix_mcp_runtime_connection_owner_seen ON mcp_runtime_connections (owner_subject, last_seen_at);

CREATE INDEX ix_mcp_runtime_connections_owner_subject ON mcp_runtime_connections (owner_subject);

CREATE INDEX ix_mcp_runtime_connections_server_id ON mcp_runtime_connections (server_id);

CREATE INDEX ix_mcp_runtime_connections_state ON mcp_runtime_connections (state);

CREATE TABLE mcp_oauth_authorization_states (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	server_id VARCHAR(36) NOT NULL,
	binding_id VARCHAR(36) NOT NULL,
	state_sha256 VARCHAR(64) NOT NULL,
	idempotency_key VARCHAR(160) NOT NULL,
	secret_blob_id VARCHAR(36) NOT NULL,
	redirect_uri TEXT NOT NULL,
	authorization_endpoint TEXT NOT NULL,
	token_endpoint TEXT NOT NULL,
	audience TEXT NOT NULL,
	scopes JSON NOT NULL,
	status VARCHAR(40) NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	used_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_oauth_authorization_owner_state UNIQUE (owner_subject, state_sha256),
	CONSTRAINT uq_mcp_oauth_authorization_owner_server_key UNIQUE (owner_subject, server_id, idempotency_key),
	FOREIGN KEY(server_id) REFERENCES mcp_servers (id),
	FOREIGN KEY(binding_id) REFERENCES mcp_credential_bindings (id),
	FOREIGN KEY(secret_blob_id) REFERENCES secret_blobs (id)
);

CREATE INDEX ix_mcp_oauth_authorization_states_secret_blob_id ON mcp_oauth_authorization_states (secret_blob_id);

CREATE INDEX ix_mcp_oauth_authorization_states_state_sha256 ON mcp_oauth_authorization_states (state_sha256);

CREATE INDEX ix_mcp_oauth_authorization_server_expires ON mcp_oauth_authorization_states (server_id, expires_at);

CREATE INDEX ix_mcp_oauth_authorization_states_owner_subject ON mcp_oauth_authorization_states (owner_subject);

CREATE INDEX ix_mcp_oauth_authorization_states_server_id ON mcp_oauth_authorization_states (server_id);

CREATE INDEX ix_mcp_oauth_authorization_states_expires_at ON mcp_oauth_authorization_states (expires_at);

CREATE INDEX ix_mcp_oauth_authorization_states_binding_id ON mcp_oauth_authorization_states (binding_id);

CREATE INDEX ix_mcp_oauth_authorization_states_status ON mcp_oauth_authorization_states (status);

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
	arguments_redacted JSON NOT NULL,
	arguments_sha256 VARCHAR(64) NOT NULL,
	preparation_id VARCHAR(36),
	approval_request_id VARCHAR(36),
	execution_permit_id VARCHAR(36),
	runtime_connection_id VARCHAR(36),
	connection_instance_id VARCHAR(160),
	thin_client_request_id VARCHAR(160),
	outcome VARCHAR(40) NOT NULL,
	unknown_outcome BOOLEAN NOT NULL,
	normalized_error_code VARCHAR(120),
	normalized_error_detail TEXT,
	response_metadata JSON NOT NULL,
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

CREATE INDEX ix_mcp_invocations_thin_client_request_id ON mcp_invocations (thin_client_request_id);

CREATE INDEX ix_mcp_invocation_owner_started ON mcp_invocations (owner_subject, started_at);

CREATE INDEX ix_mcp_invocations_gateway_tool_call_id ON mcp_invocations (gateway_tool_call_id);

CREATE INDEX ix_mcp_invocations_outcome ON mcp_invocations (outcome);

CREATE INDEX ix_mcp_invocation_outcome_started ON mcp_invocations (outcome, started_at);

CREATE INDEX ix_mcp_invocations_action_class ON mcp_invocations (action_class);

CREATE INDEX ix_mcp_invocations_server_id ON mcp_invocations (server_id);

CREATE INDEX ix_mcp_invocations_tool_id ON mcp_invocations (tool_id);

CREATE INDEX ix_mcp_invocations_revision_id ON mcp_invocations (revision_id);

CREATE INDEX ix_mcp_invocations_schema_hash ON mcp_invocations (schema_hash);

CREATE INDEX ix_mcp_invocations_preparation_id ON mcp_invocations (preparation_id);

CREATE INDEX ix_mcp_invocations_approval_request_id ON mcp_invocations (approval_request_id);

CREATE INDEX ix_mcp_invocations_execution_permit_id ON mcp_invocations (execution_permit_id);

CREATE INDEX ix_mcp_invocations_actor_subject ON mcp_invocations (actor_subject);

CREATE INDEX ix_mcp_invocations_runtime_connection_id ON mcp_invocations (runtime_connection_id);

CREATE INDEX ix_mcp_invocations_owner_subject ON mcp_invocations (owner_subject);

CREATE INDEX ix_mcp_invocations_connection_instance_id ON mcp_invocations (connection_instance_id);

CREATE INDEX ix_mcp_invocation_server_started ON mcp_invocations (server_id, started_at);

CREATE INDEX ix_mcp_invocations_correlation_id ON mcp_invocations (correlation_id);

CREATE TABLE action_receipts (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	permit_id VARCHAR(36) NOT NULL,
	approval_request_id VARCHAR(36) NOT NULL,
	command_id VARCHAR(36),
	executor_agent_id VARCHAR(36) NOT NULL,
	action_class VARCHAR(40) NOT NULL,
	tool VARCHAR(160) NOT NULL,
	command_profile VARCHAR(160),
	status VARCHAR(40) NOT NULL,
	input_hash VARCHAR(64) NOT NULL,
	output_hash VARCHAR(64),
	result_summary JSON NOT NULL,
	error TEXT,
	external_references JSON NOT NULL,
	idempotency_key VARCHAR(160),
	started_at TIMESTAMP WITH TIME ZONE NOT NULL,
	completed_at TIMESTAMP WITH TIME ZONE NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_action_receipt_permit UNIQUE (permit_id),
	CONSTRAINT uq_action_receipt_owner_idempotency UNIQUE (owner_subject, idempotency_key),
	FOREIGN KEY(permit_id) REFERENCES execution_permits (id),
	FOREIGN KEY(approval_request_id) REFERENCES approval_requests (id),
	FOREIGN KEY(command_id) REFERENCES agent_commands (id),
	FOREIGN KEY(executor_agent_id) REFERENCES agent_instances (id)
);

CREATE INDEX ix_action_receipts_owner_subject ON action_receipts (owner_subject);

CREATE INDEX ix_action_receipts_executor_agent_id ON action_receipts (executor_agent_id);

CREATE INDEX ix_action_receipts_status ON action_receipts (status);

CREATE INDEX ix_action_receipts_approval_request_id ON action_receipts (approval_request_id);

CREATE INDEX ix_action_receipts_command_id ON action_receipts (command_id);

CREATE INDEX ix_action_receipts_created_at ON action_receipts (created_at);

CREATE UNIQUE INDEX ix_action_receipts_permit_id ON action_receipts (permit_id);

CREATE INDEX ix_action_receipts_tool ON action_receipts (tool);

CREATE INDEX ix_action_receipts_action_class ON action_receipts (action_class);

CREATE TABLE mcp_projection_tools (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	generation_id VARCHAR(36) NOT NULL,
	position INTEGER NOT NULL,
	public_name VARCHAR(255) NOT NULL,
	source_exposure_id VARCHAR(36) NOT NULL,
	server_id VARCHAR(36) NOT NULL,
	tool_id VARCHAR(36) NOT NULL,
	revision_id VARCHAR(36) NOT NULL,
	source_schema_hash VARCHAR(64) NOT NULL,
	input_schema JSON NOT NULL,
	output_schema JSON,
	sanitized_title VARCHAR(240),
	sanitized_description TEXT NOT NULL,
	annotations JSON NOT NULL,
	action_class VARCHAR(40) NOT NULL,
	required_role VARCHAR(120),
	required_scope VARCHAR(160),
	approval_class VARCHAR(40) NOT NULL,
	change_classification VARCHAR(40) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_projection_tool_public_name UNIQUE (generation_id, public_name),
	CONSTRAINT uq_mcp_projection_tool_position UNIQUE (generation_id, position),
	CONSTRAINT ck_mcp_projection_tool_action_class CHECK (action_class in ('read', 'write', 'destructive', 'production')),
	CONSTRAINT ck_mcp_projection_tool_change CHECK (change_classification in ('new', 'metadata_only', 'backward_compatible_additive', 'behavior_risk', 'breaking_schema', 'removed_unavailable')),
	FOREIGN KEY(generation_id) REFERENCES mcp_projection_generations (id),
	FOREIGN KEY(source_exposure_id) REFERENCES mcp_tool_exposures (id),
	FOREIGN KEY(server_id) REFERENCES mcp_servers (id),
	FOREIGN KEY(tool_id) REFERENCES mcp_tools (id),
	FOREIGN KEY(revision_id) REFERENCES mcp_tool_revisions (id)
);

CREATE INDEX ix_mcp_projection_tools_generation_id ON mcp_projection_tools (generation_id);

CREATE INDEX ix_mcp_projection_tools_server_id ON mcp_projection_tools (server_id);

CREATE INDEX ix_mcp_projection_tools_source_schema_hash ON mcp_projection_tools (source_schema_hash);

CREATE INDEX ix_mcp_projection_tools_owner_subject ON mcp_projection_tools (owner_subject);

CREATE INDEX ix_mcp_projection_tools_action_class ON mcp_projection_tools (action_class);

CREATE INDEX ix_mcp_projection_tools_tool_id ON mcp_projection_tools (tool_id);

CREATE INDEX ix_mcp_projection_tools_change_classification ON mcp_projection_tools (change_classification);

CREATE INDEX ix_mcp_projection_tool_revision ON mcp_projection_tools (revision_id);

CREATE INDEX ix_mcp_projection_tools_source_exposure_id ON mcp_projection_tools (source_exposure_id);

CREATE INDEX ix_mcp_projection_tools_public_name ON mcp_projection_tools (public_name);

CREATE INDEX ix_mcp_projection_tools_revision_id ON mcp_projection_tools (revision_id);

CREATE INDEX ix_mcp_projection_tool_generation_position ON mcp_projection_tools (generation_id, position);

CREATE TABLE mcp_action_preparations (
	id VARCHAR(36) NOT NULL,
	owner_subject VARCHAR(255) NOT NULL,
	actor_subject VARCHAR(255) NOT NULL,
	server_id VARCHAR(36) NOT NULL,
	tool_id VARCHAR(36) NOT NULL,
	revision_id VARCHAR(36) NOT NULL,
	schema_hash VARCHAR(64) NOT NULL,
	action_class VARCHAR(40) NOT NULL,
	arguments_secret_id VARCHAR(36) NOT NULL,
	arguments_redacted JSON NOT NULL,
	arguments_sha256 VARCHAR(64) NOT NULL,
	justification TEXT NOT NULL,
	preview JSON NOT NULL,
	approval_class VARCHAR(40) NOT NULL,
	exposure_id VARCHAR(36) NOT NULL,
	exposure_version INTEGER NOT NULL,
	federation_policy_id VARCHAR(36) NOT NULL,
	federation_policy_generation INTEGER NOT NULL,
	autonomy_policy_id VARCHAR(36) NOT NULL,
	autonomy_policy_generation INTEGER NOT NULL,
	command_id VARCHAR(36) NOT NULL,
	executor_agent_id VARCHAR(36) NOT NULL,
	approval_request_id VARCHAR(36) NOT NULL,
	status VARCHAR(40) NOT NULL,
	idempotency_key VARCHAR(160) NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	executed_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_mcp_action_preparation_owner_key UNIQUE (owner_subject, idempotency_key),
	CONSTRAINT ck_mcp_action_preparation_action_class CHECK (action_class in ('write', 'destructive', 'production')),
	CONSTRAINT ck_mcp_action_preparation_status CHECK (status in ('pending_approval', 'approved', 'executing', 'succeeded', 'failed', 'expired', 'revoked')),
	FOREIGN KEY(server_id) REFERENCES mcp_servers (id),
	FOREIGN KEY(tool_id) REFERENCES mcp_tools (id),
	FOREIGN KEY(revision_id) REFERENCES mcp_tool_revisions (id),
	FOREIGN KEY(arguments_secret_id) REFERENCES secret_blobs (id),
	FOREIGN KEY(exposure_id) REFERENCES mcp_tool_exposures (id),
	FOREIGN KEY(federation_policy_id) REFERENCES mcp_federation_policies (id)
);

CREATE INDEX ix_mcp_action_preparations_actor_subject ON mcp_action_preparations (actor_subject);

CREATE INDEX ix_mcp_action_preparations_autonomy_policy_id ON mcp_action_preparations (autonomy_policy_id);

CREATE INDEX ix_mcp_action_preparations_owner_subject ON mcp_action_preparations (owner_subject);

CREATE INDEX ix_mcp_action_preparations_executor_agent_id ON mcp_action_preparations (executor_agent_id);

CREATE INDEX ix_mcp_action_preparations_action_class ON mcp_action_preparations (action_class);

CREATE UNIQUE INDEX ix_mcp_action_preparations_approval_request_id ON mcp_action_preparations (approval_request_id);

CREATE INDEX ix_mcp_action_preparation_owner_status ON mcp_action_preparations (owner_subject, status);

CREATE INDEX ix_mcp_action_preparations_server_id ON mcp_action_preparations (server_id);

CREATE INDEX ix_mcp_action_preparations_status ON mcp_action_preparations (status);

CREATE INDEX ix_mcp_action_preparation_server_created ON mcp_action_preparations (server_id, created_at);

CREATE INDEX ix_mcp_action_preparations_revision_id ON mcp_action_preparations (revision_id);

CREATE INDEX ix_mcp_action_preparations_expires_at ON mcp_action_preparations (expires_at);

CREATE INDEX ix_mcp_action_preparations_tool_id ON mcp_action_preparations (tool_id);

CREATE INDEX ix_mcp_action_preparations_created_at ON mcp_action_preparations (created_at);

CREATE INDEX ix_mcp_action_preparations_schema_hash ON mcp_action_preparations (schema_hash);

CREATE INDEX ix_mcp_action_preparations_arguments_secret_id ON mcp_action_preparations (arguments_secret_id);

CREATE INDEX ix_mcp_action_preparations_exposure_id ON mcp_action_preparations (exposure_id);

CREATE INDEX ix_mcp_action_preparations_arguments_sha256 ON mcp_action_preparations (arguments_sha256);

CREATE INDEX ix_mcp_action_preparations_command_id ON mcp_action_preparations (command_id);

CREATE INDEX ix_mcp_action_preparations_federation_policy_id ON mcp_action_preparations (federation_policy_id);

ALTER TABLE agent_instances ADD FOREIGN KEY(current_room_id) REFERENCES collaboration_rooms (id);

ALTER TABLE mcp_tool_revisions ADD FOREIGN KEY(tool_id) REFERENCES mcp_tools (id);

ALTER TABLE agent_work_items ADD FOREIGN KEY(assigned_agent_id) REFERENCES agent_instances (id);

ALTER TABLE mcp_tools ADD FOREIGN KEY(server_id) REFERENCES mcp_servers (id);

ALTER TABLE agent_work_items ADD FOREIGN KEY(room_id) REFERENCES collaboration_rooms (id);

ALTER TABLE agent_instances ADD FOREIGN KEY(current_work_item_id) REFERENCES agent_work_items (id);

ALTER TABLE mcp_tool_revisions ADD FOREIGN KEY(superseded_by_revision_id) REFERENCES mcp_tool_revisions (id);

ALTER TABLE mcp_tools ADD FOREIGN KEY(current_revision_id) REFERENCES mcp_tool_revisions (id);

ALTER TABLE mcp_tool_revisions ADD FOREIGN KEY(server_id) REFERENCES mcp_servers (id);

ALTER TABLE agent_work_items ADD FOREIGN KEY(parent_id) REFERENCES agent_work_items (id);

ALTER TABLE collaboration_rooms ADD FOREIGN KEY(created_by_agent_id) REFERENCES agent_instances (id);
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
