from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


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
