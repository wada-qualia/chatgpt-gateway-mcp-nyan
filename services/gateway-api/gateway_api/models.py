from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
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
    path: Mapped[str] = mapped_column(Text)
    operation: Mapped[str] = mapped_column(String(60), index=True)
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
