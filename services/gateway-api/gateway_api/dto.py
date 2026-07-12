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
    path: str
    operation: str
    added_lines: int
    removed_lines: int
    bytes_before: int
    bytes_after: int
    replacements: int
    diff_json: dict[str, Any]
    truncated: bool
    suppressed: bool
    created_at: datetime
