from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(120), index=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    provider: Mapped[str] = mapped_column(String(40), default="keycloak")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecretBlob(Base):
    __tablename__ = "secret_blobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(String(60))
    ciphertext: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(160))
    kind: Mapped[str] = mapped_column(String(40), default="ssh")
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(120))
    auth_type: Mapped[str] = mapped_column(String(40), default="password")
    credential_secret_id: Mapped[str | None] = mapped_column(ForeignKey("secret_blobs.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="registered")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DockerWorkspace(Base):
    __tablename__ = "docker_workspaces"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(160))
    image: Mapped[str] = mapped_column(String(255))
    container_name: Mapped[str] = mapped_column(String(180), unique=True)
    container_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="created")
    source_workspace_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    @property
    def description(self) -> str | None:
        value = (self.meta or {}).get("description")
        return value if isinstance(value, str) and value else None


class ThinClient(Base):
    __tablename__ = "thin_clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    directory: Mapped[str] = mapped_column(Text)
    agent_token_hash: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(40), default="online")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CommandSession(Base):
    __tablename__ = "command_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    origin: Mapped[str] = mapped_column(String(40), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    command: Mapped[str] = mapped_column(Text)
    cwd: Mapped[str] = mapped_column(Text, default=".")
    status: Mapped[str] = mapped_column(String(40), default="running", index=True)
    pid: Mapped[str | None] = mapped_column(String(80), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_path: Mapped[str] = mapped_column(Text)
    line_count: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CommandSessionDelivery(Base):
    __tablename__ = "command_session_deliveries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("command_sessions.id"), index=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    reason: Mapped[str] = mapped_column(String(40), index=True)
    start_line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int] = mapped_column(Integer)
    tool_call_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentToolCall(Base):
    __tablename__ = "agent_tool_calls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    tool_name: Mapped[str] = mapped_column(String(120), index=True)
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(40), default="running", index=True)
    session_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FileChangeSet(Base):
    __tablename__ = "file_change_sets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    origin: Mapped[str] = mapped_column(String(40), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    tool_call_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    room_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    lease_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    fencing_token: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    path: Mapped[str] = mapped_column(Text)
    operation: Mapped[str] = mapped_column(String(60), index=True)
    before_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    after_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    base_commit: Mapped[str | None] = mapped_column(String(128), nullable=True)
    branch_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    worktree_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_lines: Mapped[int] = mapped_column(Integer, default=0)
    removed_lines: Mapped[int] = mapped_column(Integer, default=0)
    bytes_before: Mapped[int] = mapped_column(Integer, default=0)
    bytes_after: Mapped[int] = mapped_column(Integer, default=0)
    replacements: Mapped[int] = mapped_column(Integer, default=0)
    diff_json: Mapped[dict] = mapped_column(JSON, default=dict)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    client_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    client_name: Mapped[str] = mapped_column(String(255), default="ChatGPT Connector")
    redirect_uris: Mapped[list[str]] = mapped_column(JSON, default=list)
    scope: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OAuthCode(Base):
    __tablename__ = "oauth_codes"

    code: Mapped[str] = mapped_column(String(160), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(255), index=True)
    redirect_uri: Mapped[str] = mapped_column(Text)
    code_challenge: Mapped[str] = mapped_column(String(255))
    scope: Mapped[str] = mapped_column(Text)
    subject: Mapped[str] = mapped_column(String(255), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DeviceCode(Base):
    __tablename__ = "device_codes"

    device_code: Mapped[str] = mapped_column(String(160), primary_key=True)
    user_code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    subject: Mapped[str] = mapped_column(String(255), index=True)
    scope: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(40), default="pending")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AccessGrant(Base):
    __tablename__ = "access_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    grantee_subject: Mapped[str] = mapped_column(String(255), index=True)
    resource_type: Mapped[str] = mapped_column(String(60))
    resource_id: Mapped[str] = mapped_column(String(160))
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(40), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(120), index=True)
    actor_subject: Mapped[str] = mapped_column(String(255), index=True)
    action: Mapped[str] = mapped_column(String(120))
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="success")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentInstance(Base):
    __tablename__ = "agent_instances"
    __table_args__ = (
        UniqueConstraint("owner_subject", "instance_id", name="uq_agent_instance_owner_instance"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    logical_agent_id: Mapped[str] = mapped_column(String(160), index=True)
    instance_id: Mapped[str] = mapped_column(String(160), index=True)
    display_name: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(40), default="active", index=True)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    labels: Mapped[dict] = mapped_column(JSON, default=dict)
    current_room_id: Mapped[str | None] = mapped_column(ForeignKey("collaboration_rooms.id"), nullable=True, index=True)
    current_work_item_id: Mapped[str | None] = mapped_column(ForeignKey("agent_work_items.id"), nullable=True, index=True)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollaborationRoom(Base):
    __tablename__ = "collaboration_rooms"
    __table_args__ = (
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_collaboration_room_owner_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str] = mapped_column(String(200))
    project_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    repository_identity: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    base_commit: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="active", index=True)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by_agent_id: Mapped[str | None] = mapped_column(ForeignKey("agent_instances.id"), nullable=True, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentMessage(Base):
    __tablename__ = "agent_messages"
    __table_args__ = (
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_agent_message_owner_idempotency"),
        UniqueConstraint("owner_subject", "room_id", "sequence_number", name="uq_agent_message_room_sequence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    room_id: Mapped[str] = mapped_column(ForeignKey("collaboration_rooms.id"), index=True)
    sender_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    recipient_agent_id: Mapped[str | None] = mapped_column(ForeignKey("agent_instances.id"), nullable=True, index=True)
    recipient_selector: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(60), default="information", index=True)
    body: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    priority: Mapped[int] = mapped_column(Integer, default=50, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    causation_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    sequence_number: Mapped[int] = mapped_column(Integer, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AgentMessageDelivery(Base):
    __tablename__ = "agent_message_deliveries"
    __table_args__ = (
        UniqueConstraint("message_id", "recipient_agent_id", name="uq_agent_message_delivery_recipient"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    message_id: Mapped[str] = mapped_column(ForeignKey("agent_messages.id"), index=True)
    recipient_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    status: Mapped[str] = mapped_column(String(40), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    visibility_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentCommand(Base):
    __tablename__ = "agent_commands"
    __table_args__ = (
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_agent_command_owner_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    room_id: Mapped[str] = mapped_column(ForeignKey("collaboration_rooms.id"), index=True)
    issuer_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    target_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    kind: Mapped[str] = mapped_column(String(60), default="instruction", index=True)
    instruction: Mapped[str] = mapped_column(Text)
    structured_payload: Mapped[dict] = mapped_column(JSON, default=dict)
    constraints: Mapped[dict] = mapped_column(JSON, default=dict)
    priority: Mapped[int] = mapped_column(Integer, default=50, index=True)
    status: Mapped[str] = mapped_column(String(40), default="pending", index=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    causation_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentWorkItem(Base):
    __tablename__ = "agent_work_items"
    __table_args__ = (
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_agent_work_item_owner_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    room_id: Mapped[str] = mapped_column(ForeignKey("collaboration_rooms.id"), index=True)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("agent_work_items.id"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(40), default="open", index=True)
    priority: Mapped[int] = mapped_column(Integer, default=50, index=True)
    assigned_agent_id: Mapped[str | None] = mapped_column(ForeignKey("agent_instances.id"), nullable=True, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    base_commit: Mapped[str | None] = mapped_column(String(128), nullable=True)
    dependencies: Mapped[list[str]] = mapped_column(JSON, default=list)
    acceptance_criteria: Mapped[list[str]] = mapped_column(JSON, default=list)
    required_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    assignment_constraints: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ResourceLease(Base):
    __tablename__ = "resource_leases"
    __table_args__ = (
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_resource_lease_owner_idempotency"),
        UniqueConstraint("owner_subject", "room_id", "fencing_token", name="uq_resource_lease_room_fence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    room_id: Mapped[str] = mapped_column(ForeignKey("collaboration_rooms.id"), index=True)
    holder_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    work_item_id: Mapped[str | None] = mapped_column(ForeignKey("agent_work_items.id"), nullable=True, index=True)
    origin: Mapped[str] = mapped_column(String(40), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    mode: Mapped[str] = mapped_column(String(40), default="exclusive_write", index=True)
    reservations: Mapped[list[dict]] = mapped_column(JSON, default=list)
    fencing_token: Mapped[int] = mapped_column(Integer, index=True)
    status: Mapped[str] = mapped_column(String(40), default="active", index=True)
    branch_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    worktree_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    base_commit: Mapped[str | None] = mapped_column(String(128), nullable=True)
    expected_head: Mapped[str | None] = mapped_column(String(128), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    renewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentHandoffBarrier(Base):
    __tablename__ = "agent_handoff_barriers"
    __table_args__ = (
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_agent_handoff_owner_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    room_id: Mapped[str] = mapped_column(ForeignKey("collaboration_rooms.id"), index=True)
    source_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    target_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    lease_id: Mapped[str] = mapped_column(ForeignKey("resource_leases.id"), index=True)
    expected_fencing_token: Mapped[int] = mapped_column(Integer)
    required_change_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(40), default="open", index=True)
    conflict_report: Mapped[dict] = mapped_column(JSON, default=dict)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    ready_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentIntegrationRecord(Base):
    __tablename__ = "agent_integration_records"
    __table_args__ = (
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_agent_integration_owner_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    room_id: Mapped[str] = mapped_column(ForeignKey("collaboration_rooms.id"), index=True)
    coordinator_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    target_branch: Mapped[str] = mapped_column(String(255))
    expected_target_head: Mapped[str] = mapped_column(String(128))
    candidate_change_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    comparison_change_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_lease_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(40), default="review", index=True)
    conflict_report: Mapped[dict] = mapped_column(JSON, default=dict)
    decision: Mapped[dict] = mapped_column(JSON, default=dict)
    integrated_commit: Mapped[str | None] = mapped_column(String(128), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AutonomyPolicy(Base):
    __tablename__ = "autonomy_policies"
    __table_args__ = (
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_autonomy_policy_owner_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    room_id: Mapped[str] = mapped_column(ForeignKey("collaboration_rooms.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(40), default="active", index=True)
    assignment_mode: Mapped[str] = mapped_column(String(40), default="manual", index=True)
    coordinator_agent_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_instances.id"), nullable=True, index=True
    )
    allowed_action_classes: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_tools: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_command_profiles: Mapped[list[str]] = mapped_column(JSON, default=list)
    max_parallel_assignments: Mapped[int] = mapped_column(Integer, default=1)
    approval_rules: Mapped[dict] = mapped_column(JSON, default=dict)
    recovery_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    generation: Mapped[int] = mapped_column(Integer, default=1)
    version: Mapped[int] = mapped_column(Integer, default=1)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_by_subject: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AutonomyControlState(Base):
    __tablename__ = "autonomy_control_states"
    __table_args__ = (
        UniqueConstraint(
            "owner_subject", "scope_type", "scope_id", name="uq_autonomy_control_scope"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    scope_type: Mapped[str] = mapped_column(String(40), index=True)
    scope_id: Mapped[str] = mapped_column(String(160), default="", index=True)
    state: Mapped[str] = mapped_column(String(40), default="enabled", index=True)
    generation: Mapped[int] = mapped_column(Integer, default=1)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_by_subject: Mapped[str] = mapped_column(String(255))
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AutonomyOverride(Base):
    __tablename__ = "autonomy_overrides"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    scope_type: Mapped[str] = mapped_column(String(40), index=True)
    scope_id: Mapped[str] = mapped_column(String(160), default="", index=True)
    action: Mapped[str] = mapped_column(String(60), index=True)
    previous_state: Mapped[str | None] = mapped_column(String(40), nullable=True)
    new_state: Mapped[str | None] = mapped_column(String(40), nullable=True)
    reason: Mapped[str] = mapped_column(Text)
    actor_subject: Mapped[str] = mapped_column(String(255), index=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AutonomyAssignment(Base):
    __tablename__ = "autonomy_assignments"
    __table_args__ = (
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_autonomy_assignment_owner_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    room_id: Mapped[str] = mapped_column(ForeignKey("collaboration_rooms.id"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("autonomy_policies.id"), index=True)
    work_item_id: Mapped[str] = mapped_column(ForeignKey("agent_work_items.id"), index=True)
    selected_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    status: Mapped[str] = mapped_column(String(40), default="proposed", index=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    rationale: Mapped[dict] = mapped_column(JSON, default=dict)
    policy_generation: Mapped[int] = mapped_column(Integer)
    work_item_version: Mapped[int] = mapped_column(Integer)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_by_subject: Mapped[str] = mapped_column(String(255))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"
    __table_args__ = (
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_approval_request_owner_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    room_id: Mapped[str] = mapped_column(ForeignKey("collaboration_rooms.id"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("autonomy_policies.id"), index=True)
    command_id: Mapped[str | None] = mapped_column(ForeignKey("agent_commands.id"), nullable=True, index=True)
    work_item_id: Mapped[str | None] = mapped_column(ForeignKey("agent_work_items.id"), nullable=True, index=True)
    integration_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_integration_records.id"), nullable=True, index=True
    )
    proposer_agent_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_instances.id"), nullable=True, index=True
    )
    executor_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    action_kind: Mapped[str] = mapped_column(String(120), index=True)
    action_class: Mapped[str] = mapped_column(String(40), index=True)
    tool: Mapped[str] = mapped_column(String(160), index=True)
    command_profile: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    payload_hash: Mapped[str] = mapped_column(String(64), index=True)
    payload_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    quorum_required: Mapped[int] = mapped_column(Integer, default=1)
    require_admin_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    disallow_proposer_vote: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(40), default="pending", index=True)
    policy_generation: Mapped[int] = mapped_column(Integer)
    version: Mapped[int] = mapped_column(Integer, default=1)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_by_subject: Mapped[str] = mapped_column(String(255), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApprovalVote(Base):
    __tablename__ = "approval_votes"
    __table_args__ = (
        UniqueConstraint("request_id", "voter_subject", name="uq_approval_vote_subject"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("approval_requests.id"), index=True)
    voter_subject: Mapped[str] = mapped_column(String(255), index=True)
    voter_roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    decision: Mapped[str] = mapped_column(String(40), index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ExecutionPermit(Base):
    __tablename__ = "execution_permits"
    __table_args__ = (
        UniqueConstraint("approval_request_id", name="uq_execution_permit_request"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    approval_request_id: Mapped[str] = mapped_column(ForeignKey("approval_requests.id"), unique=True, index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("autonomy_policies.id"), index=True)
    command_id: Mapped[str | None] = mapped_column(ForeignKey("agent_commands.id"), nullable=True, index=True)
    executor_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    action_class: Mapped[str] = mapped_column(String(40), index=True)
    tool: Mapped[str] = mapped_column(String(160), index=True)
    command_profile: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    payload_hash: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(40), default="active", index=True)
    policy_generation: Mapped[int] = mapped_column(Integer)
    control_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    fencing_token: Mapped[int] = mapped_column(Integer, default=1)
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    use_count: Mapped[int] = mapped_column(Integer, default=0)
    issued_by_subject: Mapped[str] = mapped_column(String(255))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionReceipt(Base):
    __tablename__ = "action_receipts"
    __table_args__ = (
        UniqueConstraint("permit_id", name="uq_action_receipt_permit"),
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_action_receipt_owner_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    permit_id: Mapped[str] = mapped_column(ForeignKey("execution_permits.id"), unique=True, index=True)
    approval_request_id: Mapped[str] = mapped_column(ForeignKey("approval_requests.id"), index=True)
    command_id: Mapped[str | None] = mapped_column(ForeignKey("agent_commands.id"), nullable=True, index=True)
    executor_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    action_class: Mapped[str] = mapped_column(String(40), index=True)
    tool: Mapped[str] = mapped_column(String(160), index=True)
    command_profile: Mapped[str | None] = mapped_column(String(160), nullable=True)
    status: Mapped[str] = mapped_column(String(40), index=True)
    input_hash: Mapped[str] = mapped_column(String(64))
    output_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    external_references: Mapped[list[dict]] = mapped_column(JSON, default=list)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class RecoveryLoop(Base):
    __tablename__ = "recovery_loops"
    __table_args__ = (
        UniqueConstraint("owner_subject", "idempotency_key", name="uq_recovery_loop_owner_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    room_id: Mapped[str] = mapped_column(ForeignKey("collaboration_rooms.id"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("autonomy_policies.id"), index=True)
    source_type: Mapped[str] = mapped_column(String(40), index=True)
    source_id: Mapped[str] = mapped_column(String(160), index=True)
    target_agent_id: Mapped[str] = mapped_column(ForeignKey("agent_instances.id"), index=True)
    strategy: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(40), default="planned", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=1)
    base_backoff_seconds: Mapped[int] = mapped_column(Integer, default=30)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_command_id: Mapped[str | None] = mapped_column(ForeignKey("agent_commands.id"), nullable=True, index=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_generation: Mapped[int] = mapped_column(Integer)
    generation: Mapped[int] = mapped_column(Integer, default=1)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_by_subject: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OutboxEvent(Base):
    __tablename__ = "outbox_events"
    __table_args__ = (
        UniqueConstraint("audit_event_id", name="uq_outbox_event_audit_event"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_event_id: Mapped[str] = mapped_column(ForeignKey("audit_events.id"), unique=True, index=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    event_type: Mapped[str] = mapped_column(String(120), index=True)
    subject: Mapped[str] = mapped_column(String(255), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(40), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=10)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    locked_by: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    lock_token: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    broker_stream: Mapped[str | None] = mapped_column(String(160), nullable=True)
    broker_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    replay_count: Mapped[int] = mapped_column(Integer, default=0)
    replayed_from_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OutboxDeliveryAttempt(Base):
    __tablename__ = "outbox_delivery_attempts"
    __table_args__ = (
        UniqueConstraint("outbox_event_id", "attempt_number", name="uq_outbox_attempt_number"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    outbox_event_id: Mapped[str] = mapped_column(ForeignKey("outbox_events.id"), index=True)
    attempt_number: Mapped[int] = mapped_column(Integer)
    replica_id: Mapped[str] = mapped_column(String(160), index=True)
    status: Mapped[str] = mapped_column(String(40), index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    broker_stream: Mapped[str | None] = mapped_column(String(160), nullable=True)
    broker_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ProcessedBrokerMessage(Base):
    __tablename__ = "processed_broker_messages"

    message_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    stream: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    consumer: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    subject: Mapped[str] = mapped_column(String(255), index=True)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class GatewayReplica(Base):
    __tablename__ = "gateway_replicas"

    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255))
    process_id: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(40), default="online", index=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RealtimeRoute(Base):
    __tablename__ = "realtime_routes"
    __table_args__ = (
        UniqueConstraint(
            "owner_subject",
            "target_kind",
            "target_id",
            "connection_id",
            name="uq_realtime_route_connection",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    target_kind: Mapped[str] = mapped_column(String(40), index=True)
    target_id: Mapped[str] = mapped_column(String(160), index=True)
    connection_id: Mapped[str] = mapped_column(String(160), index=True)
    replica_id: Mapped[str] = mapped_column(String(160), index=True)
    status: Mapped[str] = mapped_column(String(40), default="online", index=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    connected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    disconnected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RealtimeNotification(Base):
    __tablename__ = "realtime_notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    target_kind: Mapped[str] = mapped_column(String(40), index=True)
    target_id: Mapped[str] = mapped_column(String(160), index=True)
    event_type: Mapped[str] = mapped_column(String(120), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(40), default="pending", index=True)
    replica_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    outbox_event_id: Mapped[str | None] = mapped_column(ForeignKey("outbox_events.id"), nullable=True, index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
