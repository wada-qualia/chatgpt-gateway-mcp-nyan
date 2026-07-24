# ruff: noqa: I001, UP017
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy import CheckConstraint, Index
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
    preferences: Mapped[dict] = mapped_column(JSON, default=dict)
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


class McpCredentialBinding(Base):
    __tablename__ = "mcp_credential_bindings"
    __table_args__ = (
        UniqueConstraint(
            "owner_subject",
            "idempotency_key",
            name="uq_mcp_credential_binding_owner_idempotency",
        ),
        CheckConstraint(
            "binding_type in ('oauth', 'service_account', 'thin_client_local')",
            name="ck_mcp_credential_binding_type",
        ),
        Index("ix_mcp_credential_binding_owner_status", "owner_subject", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    binding_type: Mapped[str] = mapped_column(String(40), index=True)
    provider: Mapped[str | None] = mapped_column(String(120), nullable=True)
    secret_blob_id: Mapped[str | None] = mapped_column(
        ForeignKey("secret_blobs.id"), nullable=True, index=True
    )
    audience: Mapped[str | None] = mapped_column(String(512), nullable=True)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(40), default="active", index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class McpServer(Base):
    __tablename__ = "mcp_servers"
    __table_args__ = (
        UniqueConstraint(
            "owner_subject", "normalized_slug", name="uq_mcp_server_owner_slug"
        ),
        UniqueConstraint(
            "owner_subject", "idempotency_key", name="uq_mcp_server_owner_idempotency"
        ),
        CheckConstraint(
            "origin in ('gateway', 'thin_client')", name="ck_mcp_server_origin"
        ),
        CheckConstraint(
            "transport in ('streamable_http', 'legacy_sse', 'stdio', 'private_http')",
            name="ck_mcp_server_transport",
        ),
        CheckConstraint(
            "trust_level in ('unreviewed', 'restricted', 'approved', 'quarantined', 'revoked')",
            name="ck_mcp_server_trust_level",
        ),
        Index("ix_mcp_server_owner_status", "owner_subject", "status"),
        Index("ix_mcp_server_owner_trust", "owner_subject", "trust_level"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    origin: Mapped[str] = mapped_column(String(40), index=True)
    thin_client_id: Mapped[str | None] = mapped_column(
        ForeignKey("thin_clients.id"), nullable=True, index=True
    )
    runtime_id: Mapped[str | None] = mapped_column(
        String(160), nullable=True, index=True
    )
    local_server_id: Mapped[str | None] = mapped_column(
        String(160), nullable=True, index=True
    )
    display_name: Mapped[str] = mapped_column(String(180))
    normalized_slug: Mapped[str] = mapped_column(String(120))
    transport: Mapped[str] = mapped_column(String(40), index=True)
    endpoint_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    credential_binding_id: Mapped[str | None] = mapped_column(
        ForeignKey("mcp_credential_bindings.id"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(String(40), default="draft", index=True)
    trust_level: Mapped[str] = mapped_column(
        String(40), default="unreviewed", index=True
    )
    quarantine_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    negotiated_protocol_version: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    catalog_generation: Mapped[int] = mapped_column(Integer, default=0)
    policy_generation: Mapped[int] = mapped_column(Integer, default=1)
    version: Mapped[int] = mapped_column(Integer, default=1)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    last_connected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_catalog_refreshed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    disabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class McpTool(Base):
    __tablename__ = "mcp_tools"
    __table_args__ = (
        UniqueConstraint("server_id", "upstream_name", name="uq_mcp_tool_server_name"),
        Index("ix_mcp_tool_owner_state", "owner_subject", "lifecycle_state"),
        Index(
            "ix_mcp_tool_server_current_revision", "server_id", "current_revision_id"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("mcp_servers.id"), index=True)
    upstream_name: Mapped[str] = mapped_column(String(255))
    normalized_name: Mapped[str] = mapped_column(String(255), index=True)
    lifecycle_state: Mapped[str] = mapped_column(
        String(40), default="active", index=True
    )
    current_revision_id: Mapped[str | None] = mapped_column(
        ForeignKey("mcp_tool_revisions.id"), nullable=True, index=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1)
    first_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    last_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class McpToolRevision(Base):
    __tablename__ = "mcp_tool_revisions"
    __table_args__ = (
        UniqueConstraint(
            "tool_id", "revision_number", name="uq_mcp_tool_revision_number"
        ),
        UniqueConstraint(
            "tool_id", "schema_hash", name="uq_mcp_tool_revision_schema_hash"
        ),
        CheckConstraint(
            "action_class in ('unknown', 'read', 'write', 'destructive', 'production')",
            name="ck_mcp_tool_revision_action_class",
        ),
        CheckConstraint(
            "read_only_status in ('unverified', 'verified', 'rejected')",
            name="ck_mcp_tool_revision_read_only_status",
        ),
        Index("ix_mcp_tool_revision_owner_hash", "owner_subject", "schema_hash"),
        Index(
            "ix_mcp_tool_revision_server_generation", "server_id", "catalog_generation"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("mcp_servers.id"), index=True)
    tool_id: Mapped[str] = mapped_column(ForeignKey("mcp_tools.id"), index=True)
    revision_number: Mapped[int] = mapped_column(Integer)
    input_schema: Mapped[dict] = mapped_column(JSON)
    output_schema: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    sanitized_title: Mapped[str | None] = mapped_column(String(240), nullable=True)
    sanitized_description: Mapped[str] = mapped_column(Text, default="")
    search_text: Mapped[str] = mapped_column(Text, default="")
    annotations: Mapped[dict] = mapped_column(JSON, default=dict)
    schema_hash: Mapped[str] = mapped_column(String(64), index=True)
    protocol_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    catalog_generation: Mapped[int] = mapped_column(Integer)
    action_class: Mapped[str] = mapped_column(String(40), default="unknown", index=True)
    read_only_status: Mapped[str] = mapped_column(
        String(40), default="unverified", index=True
    )
    risk_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    version: Mapped[int] = mapped_column(Integer, default=1)
    classified_by_subject: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    classified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    superseded_by_revision_id: Mapped[str | None] = mapped_column(
        ForeignKey("mcp_tool_revisions.id"), nullable=True, index=True
    )
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class McpToolExposure(Base):
    __tablename__ = "mcp_tool_exposures"
    __table_args__ = (
        UniqueConstraint(
            "revision_id",
            "projection_generation",
            name="uq_mcp_tool_exposure_revision_generation",
        ),
        CheckConstraint(
            "mode in ('hidden', 'catalog_only', 'native_projected')",
            name="ck_mcp_tool_exposure_mode",
        ),
        CheckConstraint(
            "approval_class in ('none', 'operator', 'quorum', 'production')",
            name="ck_mcp_tool_exposure_approval_class",
        ),
        Index("ix_mcp_tool_exposure_owner_enabled", "owner_subject", "enabled"),
        Index("ix_mcp_tool_exposure_tool_mode", "tool_id", "mode"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("mcp_servers.id"), index=True)
    tool_id: Mapped[str] = mapped_column(ForeignKey("mcp_tools.id"), index=True)
    revision_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_tool_revisions.id"), index=True
    )
    mode: Mapped[str] = mapped_column(String(40), default="hidden", index=True)
    projected_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    required_role: Mapped[str | None] = mapped_column(String(120), nullable=True)
    required_scope: Mapped[str | None] = mapped_column(String(160), nullable=True)
    approval_class: Mapped[str] = mapped_column(String(40), default="none")
    projection_generation: Mapped[int] = mapped_column(Integer, default=0)
    policy_generation: Mapped[int] = mapped_column(Integer, default=1)
    version: Mapped[int] = mapped_column(Integer, default=1)
    reviewed_by_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class McpFederationPolicy(Base):
    __tablename__ = "mcp_federation_policies"
    __table_args__ = (
        UniqueConstraint(
            "owner_subject", "server_id", name="uq_mcp_federation_policy_owner_server"
        ),
        UniqueConstraint(
            "owner_subject",
            "idempotency_key",
            name="uq_mcp_federation_policy_owner_idempotency",
        ),
        CheckConstraint(
            "trust_level in ('unreviewed', 'restricted', 'approved', 'quarantined', 'revoked')",
            name="ck_mcp_federation_policy_trust_level",
        ),
        Index("ix_mcp_federation_policy_owner_status", "owner_subject", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    server_id: Mapped[str | None] = mapped_column(
        ForeignKey("mcp_servers.id"), nullable=True, index=True
    )
    trust_level: Mapped[str] = mapped_column(
        String(40), default="unreviewed", index=True
    )
    allowed_action_classes: Mapped[list[str]] = mapped_column(JSON, default=list)
    required_roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    required_scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    approval_mapping: Mapped[dict] = mapped_column(JSON, default=dict)
    tool_allowlist: Mapped[list[str]] = mapped_column(JSON, default=list)
    tool_denylist: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(40), default="active", index=True)
    generation: Mapped[int] = mapped_column(Integer, default=1)
    version: Mapped[int] = mapped_column(Integer, default=1)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_by_subject: Mapped[str] = mapped_column(String(255))
    updated_by_subject: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class McpRuntimeConnection(Base):
    __tablename__ = "mcp_runtime_connections"
    __table_args__ = (
        UniqueConstraint(
            "owner_subject",
            "connection_instance_id",
            name="uq_mcp_runtime_connection_instance",
        ),
        Index("ix_mcp_runtime_connection_server_state", "server_id", "state"),
        Index("ix_mcp_runtime_connection_owner_seen", "owner_subject", "last_seen_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("mcp_servers.id"), index=True)
    thin_client_id: Mapped[str | None] = mapped_column(
        ForeignKey("thin_clients.id"), nullable=True, index=True
    )
    runtime_id: Mapped[str | None] = mapped_column(
        String(160), nullable=True, index=True
    )
    connection_instance_id: Mapped[str] = mapped_column(String(160), index=True)
    supported_transports: Mapped[list[str]] = mapped_column(JSON, default=list)
    supported_protocol_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    state: Mapped[str] = mapped_column(String(40), default="online", index=True)
    acknowledged_catalog_generation: Mapped[int] = mapped_column(Integer, default=0)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    connected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    disconnected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class McpOAuthAuthorizationState(Base):
    __tablename__ = "mcp_oauth_authorization_states"
    __table_args__ = (
        UniqueConstraint(
            "owner_subject",
            "state_sha256",
            name="uq_mcp_oauth_authorization_owner_state",
        ),
        UniqueConstraint(
            "owner_subject",
            "server_id",
            "idempotency_key",
            name="uq_mcp_oauth_authorization_owner_server_key",
        ),
        Index(
            "ix_mcp_oauth_authorization_server_expires",
            "server_id",
            "expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("mcp_servers.id"), index=True)
    binding_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_credential_bindings.id"), index=True
    )
    state_sha256: Mapped[str] = mapped_column(String(64), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(160))
    secret_blob_id: Mapped[str] = mapped_column(ForeignKey("secret_blobs.id"), index=True)
    redirect_uri: Mapped[str] = mapped_column(Text)
    authorization_endpoint: Mapped[str] = mapped_column(Text)
    token_endpoint: Mapped[str] = mapped_column(Text)
    audience: Mapped[str] = mapped_column(Text)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(40), default="pending", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class McpMutationReceipt(Base):
    __tablename__ = "mcp_mutation_receipts"
    __table_args__ = (
        UniqueConstraint(
            "owner_subject",
            "operation",
            "idempotency_key",
            name="uq_mcp_mutation_receipt_owner_operation_key",
        ),
        Index(
            "ix_mcp_mutation_receipt_owner_created",
            "owner_subject",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    operation: Mapped[str] = mapped_column(String(120), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(160))
    request_hash: Mapped[str] = mapped_column(String(64))
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str] = mapped_column(String(36), index=True)
    response_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class McpActionPreparation(Base):
    __tablename__ = "mcp_action_preparations"
    __table_args__ = (
        UniqueConstraint(
            "owner_subject",
            "idempotency_key",
            name="uq_mcp_action_preparation_owner_key",
        ),
        CheckConstraint(
            "action_class in ('write', 'destructive', 'production')",
            name="ck_mcp_action_preparation_action_class",
        ),
        CheckConstraint(
            "status in ('pending_approval', 'approved', 'executing', 'succeeded', 'failed', 'expired', 'revoked')",
            name="ck_mcp_action_preparation_status",
        ),
        Index("ix_mcp_action_preparation_owner_status", "owner_subject", "status"),
        Index("ix_mcp_action_preparation_server_created", "server_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    actor_subject: Mapped[str] = mapped_column(String(255), index=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("mcp_servers.id"), index=True)
    tool_id: Mapped[str] = mapped_column(ForeignKey("mcp_tools.id"), index=True)
    revision_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_tool_revisions.id"), index=True
    )
    schema_hash: Mapped[str] = mapped_column(String(64), index=True)
    action_class: Mapped[str] = mapped_column(String(40), index=True)
    arguments_secret_id: Mapped[str] = mapped_column(
        ForeignKey("secret_blobs.id"), index=True
    )
    arguments_redacted: Mapped[dict] = mapped_column(JSON, default=dict)
    arguments_sha256: Mapped[str] = mapped_column(String(64), index=True)
    justification: Mapped[str] = mapped_column(Text)
    preview: Mapped[dict] = mapped_column(JSON, default=dict)
    approval_class: Mapped[str] = mapped_column(String(40))
    exposure_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_tool_exposures.id"), index=True
    )
    exposure_version: Mapped[int] = mapped_column(Integer)
    federation_policy_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_federation_policies.id"), index=True
    )
    federation_policy_generation: Mapped[int] = mapped_column(Integer)
    autonomy_policy_id: Mapped[str] = mapped_column(String(36), index=True)
    autonomy_policy_generation: Mapped[int] = mapped_column(Integer)
    command_id: Mapped[str] = mapped_column(String(36), index=True)
    executor_agent_id: Mapped[str] = mapped_column(String(36), index=True)
    approval_request_id: Mapped[str] = mapped_column(
        String(36), unique=True, index=True
    )
    status: Mapped[str] = mapped_column(
        String(40), default="pending_approval", index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(160))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class McpInvocation(Base):
    __tablename__ = "mcp_invocations"
    __table_args__ = (
        UniqueConstraint(
            "owner_subject",
            "idempotency_key",
            name="uq_mcp_invocation_owner_idempotency",
        ),
        CheckConstraint(
            "action_class in ('unknown', 'read', 'write', 'destructive', 'production')",
            name="ck_mcp_invocation_action_class",
        ),
        Index("ix_mcp_invocation_owner_started", "owner_subject", "started_at"),
        Index("ix_mcp_invocation_server_started", "server_id", "started_at"),
        Index("ix_mcp_invocation_outcome_started", "outcome", "started_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    actor_subject: Mapped[str] = mapped_column(String(255), index=True)
    gateway_tool_call_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    correlation_id: Mapped[str | None] = mapped_column(
        String(160), nullable=True, index=True
    )
    server_id: Mapped[str] = mapped_column(ForeignKey("mcp_servers.id"), index=True)
    tool_id: Mapped[str] = mapped_column(ForeignKey("mcp_tools.id"), index=True)
    revision_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_tool_revisions.id"), index=True
    )
    schema_hash: Mapped[str] = mapped_column(String(64), index=True)
    action_class: Mapped[str] = mapped_column(String(40), index=True)
    arguments_redacted: Mapped[dict] = mapped_column(JSON, default=dict)
    arguments_sha256: Mapped[str] = mapped_column(String(64))
    preparation_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    approval_request_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    execution_permit_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    runtime_connection_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    connection_instance_id: Mapped[str | None] = mapped_column(
        String(160), nullable=True, index=True
    )
    thin_client_request_id: Mapped[str | None] = mapped_column(
        String(160), nullable=True, index=True
    )
    outcome: Mapped[str] = mapped_column(String(40), default="running", index=True)
    unknown_outcome: Mapped[bool] = mapped_column(Boolean, default=False)
    normalized_error_code: Mapped[str | None] = mapped_column(
        String(120), nullable=True
    )
    normalized_error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    response_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class LupTaskStart(Base):
    __tablename__ = "lup_task_starts"
    __table_args__ = (
        UniqueConstraint(
            "owner_subject",
            "source_message_id",
            name="uq_lup_task_starts_owner_message",
        ),
    )

    task_usage_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_message_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    trace_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    correlation_id: Mapped[str] = mapped_column(
        String(36), nullable=False, unique=True, index=True
    )
    start_event_id: Mapped[str] = mapped_column(
        String(36), nullable=False, unique=True, index=True
    )
    receipt_status: Mapped[str] = mapped_column(String(32), nullable=False)
    receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True, unique=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    broker_provider: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stream_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    receipt_correlation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    project_attribution_status: Mapped[str] = mapped_column(String(32), nullable=False)
    project_attribution_source: Mapped[str] = mapped_column(String(32), nullable=False)
    project_atlas_project_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    project_atlas_entity_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    project_git_commit: Mapped[str | None] = mapped_column(String(128), nullable=True)
    project_git_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

class LupToolCall(Base):
    __tablename__ = "lup_tool_calls"
    __table_args__ = (
        UniqueConstraint(
            "task_usage_id",
            "callback_id",
            name="uq_lup_tool_calls_task_callback",
        ),
    )

    callback_event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    task_usage_id: Mapped[str] = mapped_column(
        ForeignKey("lup_task_starts.task_usage_id"), nullable=False, index=True
    )
    owner_subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_message_id: Mapped[str] = mapped_column(
        String(512), nullable=False, index=True
    )
    session_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    callback_id: Mapped[str] = mapped_column(String(512), nullable=False)
    tool_call_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    command_session_id: Mapped[str | None] = mapped_column(
        String(512), nullable=True, index=True
    )
    request_id: Mapped[str | None] = mapped_column(
        String(512), nullable=True, index=True
    )
    binding_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    usage_measurement: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    observation_event_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, unique=True
    )
    observation_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, unique=True
    )
    receipt_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    receipt_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, unique=True
    )
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    broker_provider: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stream_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    receipt_correlation_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class LupToolPhaseSeal(Base):
    __tablename__ = "lup_tool_phase_seals"

    task_usage_id: Mapped[str] = mapped_column(
        ForeignKey("lup_task_starts.task_usage_id"), primary_key=True
    )
    seal_event_id: Mapped[str] = mapped_column(
        String(36), nullable=False, unique=True, index=True
    )
    owner_subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_message_id: Mapped[str] = mapped_column(
        String(512), nullable=False, index=True
    )
    session_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    last_observation_event_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    last_observation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    receipt_status: Mapped[str] = mapped_column(String(32), nullable=False)
    receipt_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, unique=True
    )
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    broker_provider: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stream_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    receipt_correlation_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    sealed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class LupTaskTerminal(Base):
    __tablename__ = "lup_task_terminals"

    task_usage_id: Mapped[str] = mapped_column(
        ForeignKey("lup_task_starts.task_usage_id"), primary_key=True
    )
    terminal_event_id: Mapped[str] = mapped_column(
        String(36), nullable=False, unique=True, index=True
    )
    owner_subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_message_id: Mapped[str] = mapped_column(
        String(512), nullable=False, index=True
    )
    session_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    callback_id: Mapped[str] = mapped_column(String(512), nullable=False)
    binding_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    terminal_kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    completion_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    delivery_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    recovery_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(
        String(512), nullable=True, index=True
    )
    final_usage_measurement: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    final_observation_event_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, unique=True
    )
    final_observation_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, unique=True
    )
    observation_receipt_status: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    observation_receipt_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, unique=True
    )
    observation_accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    observation_broker_provider: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    observation_stream_sequence: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    observation_receipt_correlation_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    terminal_receipt_status: Mapped[str] = mapped_column(String(32), nullable=False)
    terminal_receipt_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, unique=True
    )
    terminal_accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    terminal_broker_provider: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    terminal_stream_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    terminal_receipt_correlation_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    terminal_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
