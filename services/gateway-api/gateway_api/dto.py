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


class WorkspaceOut(OrmModel):
    id: str
    owner_subject: str
    name: str
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


class ThinClientOut(OrmModel):
    id: str
    owner_subject: str
    hostname: str
    directory: str
    status: str
    created_at: datetime
    last_seen_at: datetime


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
