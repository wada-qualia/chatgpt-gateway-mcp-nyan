from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class OrmModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserOut(OrmModel):
    subject: str
    username: str
    email: str | None = None
    roles: list[str]
    provider: str


class AccountSettingsOut(BaseModel):
    ui_language: Literal["en", "ru"]
    ssh_command_profile: Literal["restricted", "filtered", "unrestricted"]
    ssh_command_profile_override: Literal["restricted", "filtered", "unrestricted"] | None = None
    ssh_command_profile_default: Literal["restricted", "filtered", "unrestricted"]
    raw_commands_enabled: bool
    deny_patterns_enabled: bool


class AccountSettingsUpdate(BaseModel):
    ui_language: Literal["en", "ru"] | None = None
    ssh_command_profile: Literal["inherit", "restricted", "filtered", "unrestricted"] | None = None


class DeviceCreate(BaseModel):
    name: str
    target: str = Field(description="SSH target in user@host:port form")
    auth_type: Literal["password", "private_key", "agent"] = "password"
    password: str | None = None
    private_key: str | None = None
    passphrase: str | None = None
    verify_connection: bool = False


class DeviceUpdate(BaseModel):
    name: str | None = None
    target: str | None = Field(default=None, description="SSH target in user@host:port form")
    auth_type: Literal["password", "private_key", "agent"] | None = None
    password: str | None = None
    private_key: str | None = None
    passphrase: str | None = None


class DeviceOut(OrmModel):
    id: str
    owner_subject: str
    name: str
    kind: str
    host: str
    port: int
    username: str
    auth_type: str
    status: str
    created_at: datetime
    updated_at: datetime


class WorkspaceCreate(BaseModel):
    name: str
    image: str = "ubuntu:24.04"


class WorkspaceClone(BaseModel):
    source_workspace_id: str
    name: str


class WorkspaceUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class WorkspaceExec(BaseModel):
    command: str
    timeout_seconds: int | None = None
    workdir: str = "/workspace"
    background: bool = False
    session_name: str | None = None


class WorkspaceExecOut(BaseModel):
    exit_code: int | None = None
    output: str = ""
    session_id: str | None = None
    status: str | None = None
    backgrounded: bool = False
    recommendation: str | None = None


class WorkspaceOut(OrmModel):
    id: str
    owner_subject: str
    name: str
    description: str | None = None
    image: str
    container_name: str
    container_id: str | None = None
    status: str
    source_workspace_id: str | None = None
    created_at: datetime
    updated_at: datetime


class DeviceCodeOut(BaseModel):
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int = 3


class ThinClientRegister(BaseModel):
    hostname: str
    directory: str
    labels: dict[str, str] = Field(default_factory=dict)


class ThinClientToolCall(BaseModel):
    tool: Literal["list_files", "read_file", "write_file", "run_command"]
    arguments: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int | None = None
    background: bool = False
    session_name: str | None = None


class ThinClientToolResult(BaseModel):
    ok: bool
    result: dict[str, Any] | None = None
    error: str | None = None


class ThinClientOut(OrmModel):
    id: str
    owner_subject: str
    hostname: str
    directory: str
    status: str
    meta: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    last_seen_at: datetime


class CommandLineOut(BaseModel):
    line: int
    stream: str = "stdout"
    text: str
    timestamp: str | None = None
    auto_sent: bool = False
    agent_requested: bool = False


class CommandSessionOut(OrmModel):
    id: str
    owner_subject: str
    origin: str
    resource_id: str | None = None
    name: str | None = None
    command: str
    cwd: str
    status: str
    pid: str | None = None
    exit_code: int | None = None
    line_count: int
    truncated: bool
    meta: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    started_at: datetime
    completed_at: datetime | None = None
    updated_at: datetime


class CommandSessionOutputOut(BaseModel):
    session_id: str
    start_line: int
    end_line: int
    total_lines: int
    lines: list[CommandLineOut]


class CommandSessionTerminate(BaseModel):
    force: bool = False


class AgentToolCallOut(OrmModel):
    id: str
    tool_name: str
    arguments: dict[str, Any]
    status: str
    session_id: str | None = None
    error: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


class AccessGrantCreate(BaseModel):
    grantee_subject: str
    resource_type: str
    resource_id: str
    scopes: list[str]


class AccessGrantOut(OrmModel):
    id: str
    owner_subject: str
    grantee_subject: str
    resource_type: str
    resource_id: str
    scopes: list[str]
    status: str
    created_at: datetime


class AuditEventOut(OrmModel):
    id: str
    event_type: str
    actor_subject: str
    action: str
    resource_type: str
    resource_id: str | None = None
    status: str
    payload: dict[str, Any]
    created_at: datetime


class FileChangeSetOut(OrmModel):
    id: str
    owner_subject: str
    origin: str
    resource_id: str | None = None
    tool_call_id: str | None = None
    room_id: str | None = None
    agent_id: str | None = None
    lease_id: str | None = None
    fencing_token: int | None = None
    path: str
    operation: str
    before_sha256: str | None = None
    after_sha256: str | None = None
    base_commit: str | None = None
    branch_name: str | None = None
    worktree_path: str | None = None
    added_lines: int
    removed_lines: int
    bytes_before: int
    bytes_after: int
    replacements: int
    diff_json: dict[str, Any]
    truncated: bool
    suppressed: bool
    created_at: datetime


class AgentRegister(BaseModel):
    logical_agent_id: str
    instance_id: str
    display_name: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    labels: dict[str, Any] = Field(default_factory=dict)
    room_id: str | None = None
    ttl_seconds: int = 120


class AgentHeartbeat(BaseModel):
    status: Literal["active", "busy", "idle"] = "active"
    capabilities: list[str] | None = None
    labels: dict[str, Any] | None = None
    room_id: str | None = None
    ttl_seconds: int = 120


class CollaborationRoomCreate(BaseModel):
    title: str
    project_path: str | None = None
    repository_identity: str | None = None
    base_commit: str | None = None
    policy: dict[str, Any] = Field(default_factory=dict)
    created_by_agent_id: str | None = None
    idempotency_key: str | None = None


class CollaborationRoomJoin(BaseModel):
    agent_id: str


class AgentMessageCreate(BaseModel):
    room_id: str
    sender_agent_id: str
    recipient_agent_id: str | None = None
    recipient_selector: Literal["all", "room"] | None = None
    kind: str = "information"
    body: str
    payload: dict[str, Any] = Field(default_factory=dict)
    priority: int = 50
    correlation_id: str | None = None
    causation_id: str | None = None
    idempotency_key: str | None = None


class AgentCommandCreate(BaseModel):
    room_id: str
    issuer_agent_id: str
    target_agent_id: str
    kind: Literal[
        "handoff", "instruction", "pause", "resume", "review_request", "run_tool"
    ] = "instruction"
    instruction: str
    structured_payload: dict[str, Any] = Field(default_factory=dict)
    constraints: dict[str, Any] = Field(default_factory=dict)
    priority: int = 50
    requires_approval: bool = False
    correlation_id: str | None = None
    causation_id: str | None = None
    idempotency_key: str | None = None


class AgentCommandReject(BaseModel):
    error: str | None = None


class AgentCommandComplete(BaseModel):
    status: Literal["completed", "failed"]
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class AgentWorkItemCreate(BaseModel):
    room_id: str
    parent_id: str | None = None
    title: str
    description: str = ""
    priority: int = 50
    base_commit: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    acceptance_criteria: list[str] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    assignment_constraints: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = None


class AgentWorkItemClaim(BaseModel):
    agent_id: str
    expected_version: int = 1


class AgentWorkItemUpdate(BaseModel):
    agent_id: str
    expected_version: int
    status: Literal[
        "blocked", "cancelled", "completed", "failed", "in_progress", "review"
    ]
    description: str | None = None
    result: dict[str, Any] | None = None


class ResourceReservationIn(BaseModel):
    kind: Literal["path", "glob"] = "path"
    pattern: str
    recursive: bool = True


class ResourceLeaseAcquire(BaseModel):
    room_id: str
    holder_agent_id: str
    work_item_id: str | None = None
    origin: Literal["server", "thin_client", "docker"]
    resource_id: str | None = None
    mode: Literal["exclusive_write", "shared_read"] = "exclusive_write"
    reservations: list[ResourceReservationIn]
    branch_name: str | None = None
    worktree_path: str | None = None
    base_commit: str | None = None
    expected_head: str | None = None
    ttl_seconds: int = 300
    idempotency_key: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class ResourceLeaseRenew(BaseModel):
    holder_agent_id: str
    fencing_token: int
    ttl_seconds: int = 300


class ResourceLeaseRelease(BaseModel):
    actor_agent_id: str
    fencing_token: int
    force: bool = False


class FileConflictDetect(BaseModel):
    candidate_change_ids: list[str]
    comparison_change_ids: list[str] | None = None
    room_id: str | None = None


class AgentHandoffCreate(BaseModel):
    room_id: str
    source_agent_id: str
    target_agent_id: str
    lease_id: str
    expected_fencing_token: int
    required_change_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = None


class AgentHandoffReady(BaseModel):
    source_agent_id: str


class AgentHandoffAccept(BaseModel):
    target_agent_id: str
    comparison_change_ids: list[str] | None = None


class AgentIntegrationCreate(BaseModel):
    room_id: str
    coordinator_agent_id: str
    target_branch: str
    expected_target_head: str
    candidate_change_ids: list[str]
    comparison_change_ids: list[str] = Field(default_factory=list)
    source_lease_ids: list[str] = Field(default_factory=list)
    idempotency_key: str | None = None


class AgentIntegrationUpdate(BaseModel):
    coordinator_agent_id: str
    expected_version: int
    status: Literal["approved", "integrated", "rejected"]
    observed_target_head: str | None = None
    decision: dict[str, Any] = Field(default_factory=dict)
    integrated_commit: str | None = None


class AutonomyPolicyCreate(BaseModel):
    room_id: str
    name: str
    assignment_mode: Literal["manual", "suggest", "automatic"] = "manual"
    coordinator_agent_id: str | None = None
    allowed_action_classes: list[Literal["read", "write", "destructive", "production"]] = Field(
        default_factory=lambda: ["read"]
    )
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_command_profiles: list[str] = Field(default_factory=list)
    max_parallel_assignments: int = 1
    approval_rules: dict[str, Any] = Field(default_factory=dict)
    recovery_policy: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = None


class AutonomyPolicyUpdate(BaseModel):
    expected_version: int
    name: str | None = None
    status: Literal["active", "paused", "disabled"] | None = None
    assignment_mode: Literal["manual", "suggest", "automatic"] | None = None
    coordinator_agent_id: str | None = None
    allowed_action_classes: list[Literal["read", "write", "destructive", "production"]] | None = None
    allowed_tools: list[str] | None = None
    allowed_command_profiles: list[str] | None = None
    max_parallel_assignments: int | None = None
    approval_rules: dict[str, Any] | None = None
    recovery_policy: dict[str, Any] | None = None


class AutonomyControlUpdate(BaseModel):
    scope_type: Literal["global", "tenant", "room", "policy"]
    scope_id: str | None = None
    state: Literal["enabled", "paused", "killed"]
    reason: str
    expires_at: datetime | None = None


class AutonomyOverrideCreate(BaseModel):
    action: Literal[
        "force_assign",
        "revoke_assignment",
        "revoke_permits",
        "cancel_recoveries",
    ]
    reason: str
    room_id: str | None = None
    policy_id: str | None = None
    work_item_id: str | None = None
    agent_id: str | None = None
    assignment_id: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class ApprovalRequestCreate(BaseModel):
    policy_id: str
    command_id: str
    executor_agent_id: str
    action_class: Literal["read", "write", "destructive", "production"]
    action_kind: str = "run_tool"
    ttl_seconds: int | None = None
    idempotency_key: str | None = None


class ApprovalVoteCreate(BaseModel):
    decision: Literal["approve", "reject"]
    reason: str | None = None


class ExecutionPermitIssue(BaseModel):
    ttl_seconds: int | None = None


class ExecutionPermitClaim(BaseModel):
    executor_agent_id: str


class ActionReceiptCreate(BaseModel):
    permit_id: str
    executor_agent_id: str
    fencing_token: int
    status: Literal["succeeded", "failed", "partial", "unknown"]
    result_summary: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    external_references: list[dict[str, Any]] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime
    idempotency_key: str | None = None


class RecoveryLoopCreate(BaseModel):
    policy_id: str
    room_id: str
    source_type: Literal["command", "work_item", "action_receipt"]
    source_id: str
    target_agent_id: str
    strategy: dict[str, Any]
    max_attempts: int | None = None
    base_backoff_seconds: int | None = None
    idempotency_key: str | None = None


class RecoveryOutcomeCreate(BaseModel):
    status: Literal["succeeded", "failed", "cancelled"]
    command_id: str | None = None
    error: str | None = None


class OutboxEventOut(OrmModel):
    id: str
    audit_event_id: str
    owner_subject: str
    event_type: str
    subject: str
    payload: dict[str, Any]
    headers: dict[str, Any]
    status: str
    attempt_count: int
    max_attempts: int
    available_at: datetime
    locked_by: str | None = None
    locked_at: datetime | None = None
    published_at: datetime | None = None
    broker_stream: str | None = None
    broker_sequence: int | None = None
    last_error: str | None = None
    replay_count: int
    replayed_from_id: str | None = None
    created_at: datetime
    updated_at: datetime


class OutboxDeliveryAttemptOut(OrmModel):
    id: str
    outbox_event_id: str
    attempt_number: int
    replica_id: str
    status: str
    error: str | None = None
    broker_stream: str | None = None
    broker_sequence: int | None = None
    started_at: datetime
    completed_at: datetime | None = None


class OutboxReplayRequest(BaseModel):
    reason: str | None = None


class GatewayReplicaOut(OrmModel):
    id: str
    hostname: str
    process_id: int
    status: str
    meta: dict[str, Any]
    started_at: datetime
    last_heartbeat_at: datetime
    expires_at: datetime
    stopped_at: datetime | None = None


class RealtimeRouteOut(OrmModel):
    id: str
    owner_subject: str
    target_kind: str
    target_id: str
    connection_id: str
    replica_id: str
    status: str
    meta: dict[str, Any]
    connected_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    disconnected_at: datetime | None = None


class RealtimeNotificationOut(OrmModel):
    id: str
    owner_subject: str
    target_kind: str
    target_id: str
    event_type: str
    payload: dict[str, Any]
    status: str
    replica_id: str | None = None
    outbox_event_id: str | None = None
    attempt_count: int
    delivered_at: datetime | None = None
    acknowledged_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class LupTaskStartCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_message_id: str = Field(min_length=1, max_length=512)
    session_id: str = Field(min_length=1, max_length=512)
    trace_id: str | None = Field(default=None, min_length=32, max_length=32)

    @field_validator("trace_id")
    @classmethod
    def validate_trace_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.lower()
        if len(normalized) != 32 or any(character not in "0123456789abcdef" for character in normalized):
            raise ValueError("trace_id must be a 32-character lowercase hexadecimal W3C trace id")
        if normalized == "0" * 32:
            raise ValueError("trace_id must not be all zeros")
        return normalized


class LupTaskStartOut(BaseModel):
    task_usage_id: str
    correlation_id: str
    start_event_id: str
    source_message_id: str
    session_id: str
    trace_id: str | None = None
    receipt_status: Literal["accepted", "duplicate"]
    receipt_id: str | None = None
    accepted_at: datetime | None = None
    broker_provider: str | None = None
    stream_sequence: int | None = None
    receipt_correlation_id: str | None = None
    project_attribution_status: str
    project_attribution_source: str
    project_atlas_project_key: str | None = None
    project_atlas_entity_id: str | None = None
    project_git_commit: str | None = None
    project_git_branch: str | None = None
    sdk_version: Literal["0.1.0a0"] = "0.1.0a0"
    created: bool
    created_at: datetime
    updated_at: datetime

class LupModelIdentityCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    provider: str = Field(min_length=1, max_length=128)
    requested_model: str = Field(min_length=1, max_length=256)
    resolved_model: str = Field(min_length=1, max_length=256)
    model_revision: str | None = Field(default=None, min_length=1, max_length=2048)


class LupTokenCountsCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    reasoning_tokens: int | None = Field(default=None, ge=0)
    cache_read_tokens: int | None = Field(default=None, ge=0)
    cache_write_tokens: int | None = Field(default=None, ge=0)
    provider_total_tokens: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def require_measured_category(self) -> "LupTokenCountsCreate":
        if all(value is None for value in self.model_dump().values()):
            raise ValueError("tokens must contain at least one measured category")
        return self


class LupEstimationEvidenceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    estimator_profile_id: str = Field(min_length=1, max_length=128)
    estimator_version: str = Field(min_length=1, max_length=64)
    confidence: float = Field(ge=0, le=1)
    lower_bound_tokens: int = Field(ge=0)
    upper_bound_tokens: int = Field(ge=0)
    covered_inputs: list[
        Literal[
            "user_text",
            "visible_tool_arguments",
            "visible_tool_results",
            "final_response",
            "reasoning_numeric_estimate",
        ]
    ] = Field(default_factory=list, max_length=5)
    excluded_inputs: list[
        Literal[
            "system_context",
            "hidden_reasoning",
            "provider_transformations",
            "cached_context",
            "unknown_internal_calls",
        ]
    ] = Field(default_factory=list, max_length=5)
    evidence_ref: str | None = Field(default=None, min_length=1, max_length=2048)

    @model_validator(mode="after")
    def validate_bounds(self) -> "LupEstimationEvidenceCreate":
        if self.lower_bound_tokens > self.upper_bound_tokens:
            raise ValueError("estimation bounds are inverted")
        if len(set(self.covered_inputs)) != len(self.covered_inputs):
            raise ValueError("covered_inputs must not contain duplicates")
        if len(set(self.excluded_inputs)) != len(self.excluded_inputs):
            raise ValueError("excluded_inputs must not contain duplicates")
        return self


class LupToolUsageCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: LupModelIdentityCreate
    tokens: LupTokenCountsCreate
    measurement_kind: Literal[
        "provider_exact",
        "provider_partial",
        "tokenizer_estimate",
        "heuristic_estimate",
    ]
    covered_categories: list[
        Literal[
            "input",
            "output",
            "reasoning",
            "cache_read",
            "cache_write",
            "provider_total",
        ]
    ] = Field(min_length=1, max_length=6)
    estimation: LupEstimationEvidenceCreate | None = None

    @model_validator(mode="after")
    def validate_measurement(self) -> "LupToolUsageCreate":
        if len(set(self.covered_categories)) != len(self.covered_categories):
            raise ValueError("covered_categories must not contain duplicates")
        if (
            self.measurement_kind in {"tokenizer_estimate", "heuristic_estimate"}
            and self.estimation is None
        ):
            raise ValueError("estimated measurements require estimation evidence")
        if self.measurement_kind == "provider_exact" and self.estimation is not None:
            raise ValueError(
                "provider_exact measurements cannot contain estimation evidence"
            )
        provided = {
            name.removesuffix("_tokens")
            for name, value in self.tokens.model_dump().items()
            if value is not None
        }
        if any(category not in provided for category in self.covered_categories):
            raise ValueError(
                "covered_categories must correspond to provided token counts"
            )
        return self


class LupToolCallCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_message_id: str = Field(min_length=1, max_length=512)
    session_id: str = Field(min_length=1, max_length=512)
    callback_id: str = Field(min_length=1, max_length=512)
    tool_call_id: str = Field(min_length=1, max_length=512)
    command_session_id: str | None = Field(default=None, min_length=1, max_length=512)
    request_id: str | None = Field(default=None, min_length=1, max_length=512)
    occurred_at: datetime | None = None
    usage: LupToolUsageCreate | None = None

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("occurred_at must include a timezone")
        return value


class LupToolCallOut(BaseModel):
    callback_event_id: str
    task_usage_id: str
    correlation_id: str
    source_message_id: str
    session_id: str
    callback_id: str
    tool_call_id: str
    command_session_id: str | None = None
    request_id: str | None = None
    observation_event_id: str | None = None
    observation_id: str | None = None
    observation_published: bool
    receipt_status: Literal["accepted", "duplicate"] | None = None
    receipt_id: str | None = None
    accepted_at: datetime | None = None
    broker_provider: str | None = None
    stream_sequence: int | None = None
    receipt_correlation_id: str | None = None
    occurred_at: datetime
    created: bool
    created_at: datetime
    updated_at: datetime


class LupToolPhaseSealCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_message_id: str = Field(min_length=1, max_length=512)
    session_id: str = Field(min_length=1, max_length=512)
    sealed_at: datetime | None = None

    @field_validator("sealed_at")
    @classmethod
    def validate_sealed_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("sealed_at must include a timezone")
        return value


class LupToolPhaseSealOut(BaseModel):
    seal_event_id: str
    task_usage_id: str
    correlation_id: str
    source_message_id: str
    session_id: str
    last_observation_event_id: str | None = None
    last_observation_id: str | None = None
    receipt_status: Literal["accepted", "duplicate"]
    receipt_id: str | None = None
    accepted_at: datetime | None = None
    broker_provider: str | None = None
    stream_sequence: int | None = None
    receipt_correlation_id: str | None = None
    sealed_at: datetime
    created: bool
    created_at: datetime
    updated_at: datetime

class McpStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class McpCredentialBindingCreate(McpStrictModel):
    binding_type: Literal["oauth", "service_account", "thin_client_local"]
    provider: str | None = Field(default=None, max_length=120)
    secret_blob_id: str | None = Field(default=None, max_length=36)
    audience: str | None = Field(default=None, max_length=512)
    scopes: list[str] = Field(default_factory=list, max_length=100)
    meta: dict[str, Any] = Field(default_factory=dict)


class McpCredentialBindingOut(OrmModel):
    id: str
    owner_subject: str
    binding_type: str
    provider: str | None = None
    audience: str | None = None
    scopes: list[str]
    status: str
    version: int
    meta: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    rotated_at: datetime | None = None
    revoked_at: datetime | None = None


class McpServerCreate(McpStrictModel):
    display_name: str = Field(min_length=1, max_length=180)
    origin: Literal["gateway", "thin_client"]
    transport: Literal["streamable_http", "legacy_sse", "stdio", "private_http"]
    endpoint_url: str | None = Field(default=None, max_length=2048)
    thin_client_id: str | None = Field(default=None, max_length=36)
    runtime_id: str | None = Field(default=None, max_length=160)
    credential_binding_id: str | None = Field(default=None, max_length=36)

    @model_validator(mode="after")
    def validate_origin_transport(self) -> "McpServerCreate":
        if self.origin == "gateway":
            if self.transport not in {"streamable_http", "legacy_sse"}:
                raise ValueError("Gateway-origin MCP servers require an HTTP transport")
            if not self.endpoint_url:
                raise ValueError("Gateway-origin MCP servers require endpoint_url")
            if self.thin_client_id or self.runtime_id:
                raise ValueError(
                    "Gateway-origin MCP servers cannot select a thin-client runtime"
                )
        else:
            if self.transport not in {"stdio", "streamable_http", "private_http"}:
                raise ValueError(
                    "Thin-client MCP servers use stdio, streamable_http or private_http"
                )
            if not self.thin_client_id or not self.runtime_id:
                raise ValueError(
                    "Thin-client MCP servers require thin_client_id and runtime_id"
                )
        return self


class McpServerUpdate(McpStrictModel):
    expected_version: int = Field(ge=1)
    display_name: str | None = Field(default=None, min_length=1, max_length=180)
    credential_binding_id: str | None = Field(default=None, max_length=36)
    enabled: bool | None = None


class McpServerOut(OrmModel):
    id: str
    owner_subject: str
    origin: str
    thin_client_id: str | None = None
    runtime_id: str | None = None
    display_name: str
    normalized_slug: str
    transport: str
    endpoint_url: str | None = None
    credential_binding_id: str | None = None
    status: str
    trust_level: str
    quarantine_reason: str | None = None
    negotiated_protocol_version: str | None = None
    capabilities: dict[str, Any]
    catalog_generation: int
    policy_generation: int
    version: int
    last_connected_at: datetime | None = None
    last_catalog_refreshed_at: datetime | None = None
    disabled_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class McpServerCommand(McpStrictModel):
    expected_version: int = Field(ge=1)


class McpServerHealthOut(BaseModel):
    server_id: str
    status: str
    trust_level: str
    catalog_generation: int
    negotiated_protocol_version: str | None = None
    last_connected_at: datetime | None = None
    last_catalog_refreshed_at: datetime | None = None
    latency_ms: int | None = None
    tool_count: int | None = None
    session_id_present: bool | None = None
    circuit_state: Literal["closed", "open", "half_open"] = "closed"
    normalized_error_code: str | None = None


class McpFederationPolicyUpdate(McpStrictModel):
    expected_version: int = Field(ge=0)
    trust_level: Literal[
        "unreviewed", "restricted", "approved", "quarantined", "revoked"
    ]
    allowed_action_classes: list[
        Literal["read", "write", "destructive", "production"]
    ] = Field(default_factory=list, max_length=4)
    required_roles: list[str] = Field(default_factory=list, max_length=50)
    required_scopes: list[str] = Field(default_factory=list, max_length=100)
    approval_mapping: dict[str, Literal["none", "operator", "quorum", "production"]] = (
        Field(default_factory=dict)
    )
    tool_allowlist: list[str] = Field(default_factory=list, max_length=500)
    tool_denylist: list[str] = Field(default_factory=list, max_length=500)
    status: Literal["active", "disabled"] = "active"


class McpFederationPolicyOut(OrmModel):
    id: str
    owner_subject: str
    server_id: str | None = None
    trust_level: str
    allowed_action_classes: list[str]
    required_roles: list[str]
    required_scopes: list[str]
    approval_mapping: dict[str, str]
    tool_allowlist: list[str]
    tool_denylist: list[str]
    status: str
    generation: int
    version: int
    created_by_subject: str
    updated_by_subject: str
    created_at: datetime
    updated_at: datetime


class McpToolRevisionClassification(McpStrictModel):
    expected_version: int = Field(ge=1)
    action_class: Literal["read", "write", "destructive", "production"]
    read_only_status: Literal["unverified", "verified", "rejected"]


class McpToolRevisionOut(OrmModel):
    id: str
    owner_subject: str
    server_id: str
    tool_id: str
    revision_number: int
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    sanitized_title: str | None = None
    sanitized_description: str
    annotations: dict[str, Any]
    schema_hash: str
    protocol_version: str | None = None
    catalog_generation: int
    action_class: str
    read_only_status: str
    risk_evidence: dict[str, Any]
    version: int
    classified_by_subject: str | None = None
    classified_at: datetime | None = None
    superseded_by_revision_id: str | None = None
    discovered_at: datetime
    created_at: datetime


class McpToolOut(OrmModel):
    id: str
    owner_subject: str
    server_id: str
    upstream_name: str
    normalized_name: str
    lifecycle_state: str
    current_revision_id: str | None = None
    version: int
    first_observed_at: datetime
    last_observed_at: datetime
    created_at: datetime
    updated_at: datetime


class McpToolExposureUpdate(McpStrictModel):
    expected_version: int = Field(ge=0)
    revision_id: str = Field(max_length=36)
    mode: Literal["hidden", "catalog_only", "native_projected"]
    enabled: bool
    projected_name: str | None = Field(default=None, max_length=255)
    required_role: str | None = Field(default=None, max_length=120)
    required_scope: str | None = Field(default=None, max_length=160)
    approval_class: Literal["none", "operator", "quorum", "production"]
    projection_generation: int = Field(default=0, ge=0)


class McpToolExposureOut(OrmModel):
    id: str
    owner_subject: str
    server_id: str
    tool_id: str
    revision_id: str
    mode: str
    projected_name: str | None = None
    enabled: bool
    required_role: str | None = None
    required_scope: str | None = None
    approval_class: str
    projection_generation: int
    policy_generation: int
    version: int
    reviewed_by_subject: str | None = None
    reviewed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class McpInvocationOut(OrmModel):
    id: str
    owner_subject: str
    actor_subject: str
    gateway_tool_call_id: str | None = None
    correlation_id: str | None = None
    server_id: str
    tool_id: str
    revision_id: str
    schema_hash: str
    action_class: str
    arguments_redacted: dict[str, Any]
    arguments_sha256: str
    preparation_id: str | None = None
    approval_request_id: str | None = None
    execution_permit_id: str | None = None
    outcome: str
    unknown_outcome: bool
    normalized_error_code: str | None = None
    normalized_error_detail: str | None = None
    response_metadata: dict[str, Any]
    response_sha256: str | None = None
    started_at: datetime
    completed_at: datetime | None = None
    created_at: datetime


class McpRuntimeConnectionOut(OrmModel):
    id: str
    owner_subject: str
    server_id: str
    thin_client_id: str | None = None
    runtime_id: str | None = None
    connection_instance_id: str
    supported_transports: list[str]
    supported_protocol_versions: list[str]
    state: str
    acknowledged_catalog_generation: int
    meta: dict[str, Any]
    connected_at: datetime
    last_seen_at: datetime
    disconnected_at: datetime | None = None


class McpCatalogSearchInput(McpStrictModel):
    query: str = Field(min_length=1, max_length=512)
    server_id: str | None = Field(default=None, max_length=36)
    limit: int = Field(default=20, ge=1, le=50)


class McpToolDescribeInput(McpStrictModel):
    tool_ref: str = Field(min_length=1, max_length=512)
    schema_hash: str = Field(min_length=64, max_length=64)


class McpCallReadInput(McpStrictModel):
    tool_ref: str = Field(min_length=1, max_length=512)
    schema_hash: str = Field(min_length=64, max_length=64)
    arguments: dict[str, Any]

    @field_validator("arguments")
    @classmethod
    def reject_reserved_identity_fields(cls, value: dict[str, Any]) -> dict[str, Any]:
        forbidden = {
            "tenant",
            "tenant_id",
            "owner_subject",
            "principal",
            "actor_subject",
            "credential",
            "credential_id",
            "risk_class",
            "action_class",
            "trust_level",
        }
        present = sorted(forbidden.intersection(value))
        if present:
            raise ValueError("Caller-controlled identity or trust fields are forbidden")
        return value


class McpActionPrepareInput(McpCallReadInput):
    justification: str = Field(min_length=1, max_length=2000)
    idempotency_key: str = Field(min_length=1, max_length=160)


class McpActionExecuteInput(McpStrictModel):
    preparation_id: str = Field(max_length=36)
    permit_id: str = Field(max_length=36)
    expected_schema_hash: str = Field(min_length=64, max_length=64)
