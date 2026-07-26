from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, SecretStr, model_validator


class McpUpstreamStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class McpCredentialMaterialCreate(McpUpstreamStrictModel):
    binding_type: Literal["oauth", "service_account"]
    provider: str | None = Field(default=None, max_length=120)
    audience: HttpUrl | None = None
    scopes: list[str] = Field(default_factory=list, max_length=100)
    mode: Literal["bearer", "header", "oauth"]
    access_token: SecretStr | None = None
    refresh_token: SecretStr | None = None
    token_endpoint: HttpUrl | None = None
    client_id: str | None = Field(default=None, max_length=512)
    client_secret: SecretStr | None = None
    expires_at: datetime | None = None
    header_name: str | None = Field(default=None, min_length=1, max_length=120)
    header_value: SecretStr | None = None

    @model_validator(mode="after")
    def validate_material(self) -> "McpCredentialMaterialCreate":
        if self.binding_type == "oauth":
            if self.mode != "oauth":
                raise ValueError("OAuth bindings require mode=oauth")
            if self.audience is None:
                raise ValueError("OAuth bindings require an explicit resource audience")
            if self.access_token is None and self.refresh_token is None:
                raise ValueError("OAuth bindings require an access or refresh token")
            if self.refresh_token is not None and self.token_endpoint is None:
                raise ValueError("OAuth refresh tokens require a token endpoint")
        else:
            if self.mode == "oauth":
                raise ValueError("Service-account bindings cannot use OAuth mode")
            if self.mode == "bearer" and self.access_token is None:
                raise ValueError("Bearer service accounts require an access token")
            if self.mode == "header" and (
                self.header_name is None or self.header_value is None
            ):
                raise ValueError("Header service accounts require header_name and header_value")
        return self


class McpCredentialMaterialRotate(McpCredentialMaterialCreate):
    expected_version: int = Field(ge=1)


class McpCredentialCommand(McpUpstreamStrictModel):
    expected_version: int = Field(ge=1)


class McpOAuthDiscoveryRequest(McpUpstreamStrictModel):
    expected_version: int = Field(ge=1)
    requested_scopes: list[str] = Field(default_factory=list, max_length=100)
    authorization_server: HttpUrl | None = None


class McpOAuthDiscoveryOut(BaseModel):
    id: str
    server_id: str
    resource: str
    resource_metadata_url: str
    authorization_server: str
    authorization_server_metadata_url: str
    discovery_mechanism: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None = None
    requested_scopes: list[str]
    proposed_scopes: list[str]
    metadata_hash: str
    expires_at: datetime
    created_at: datetime


class McpOAuthAuthorizationStart(McpUpstreamStrictModel):
    expected_version: int = Field(ge=1)
    discovery_snapshot_id: str | None = Field(default=None, max_length=36)
    authorization_endpoint: HttpUrl | None = None
    token_endpoint: HttpUrl | None = None
    client_id: str = Field(min_length=1, max_length=512)
    client_secret: SecretStr | None = None
    redirect_uri: HttpUrl
    scopes: list[str] = Field(default_factory=list, max_length=100)
    audience: HttpUrl | None = None
    extra_authorization_parameters: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_discovery_binding(self) -> "McpOAuthAuthorizationStart":
        if self.discovery_snapshot_id is None and (
            self.authorization_endpoint is None
            or self.token_endpoint is None
            or self.audience is None
        ):
            raise ValueError(
                "OAuth authorization requires discovery_snapshot_id or explicit endpoints and audience"
            )
        return self


class McpOAuthAuthorizationStarted(BaseModel):
    server_id: str
    binding_id: str
    authorization_url: str
    state: str
    expires_at: datetime


class McpOAuthAuthorizationComplete(McpUpstreamStrictModel):
    state: str = Field(min_length=20, max_length=512)
    code: SecretStr


class McpUpstreamCallInput(McpUpstreamStrictModel):
    revision_id: str = Field(min_length=1, max_length=36)
    arguments: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=30.0, ge=0.1, le=300.0)


class McpUpstreamCallOut(BaseModel):
    revision_id: str
    schema_hash: str
    result: dict[str, Any]
    truncated: bool
    serialized_bytes: int
