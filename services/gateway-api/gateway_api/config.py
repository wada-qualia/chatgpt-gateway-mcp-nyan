from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ChatGPT MCP SSH Gateway"
    public_base_url: str = "http://localhost:8000"
    database_url: str = "sqlite:///./data/gateway.db"
    gateway_secret_key: str | None = None
    gateway_jwt_secret: str = "change-me-local-jwt-secret"
    gateway_session_cookie: str = "gateway_session"
    gateway_dev_auth: bool = True
    gateway_dev_subject: str = "dev:local"
    gateway_dev_username: str = "darius"
    gateway_dev_email: str | None = "local@example.invalid"
    gateway_dev_roles: str = "gateway-admin,gateway-user,gateway-auditor"
    gateway_access_token_ttl_seconds: int = 28800
    gateway_auth_code_ttl_seconds: int = 600
    gateway_device_code_ttl_seconds: int = 900
    keycloak_issuer: str = "http://localhost:8080/realms/chatgpt-mcp"
    keycloak_client_id: str = "chatgpt-mcp-gateway"
    keycloak_client_secret: str = ""
    oauth_audience: str = "chatgpt-mcp-ssh-gateway"
    oauth_supported_scopes: str = "workspace:read workspace:write workspace:exec devices:manage docker:manage audit:read"
    gateway_docker_enabled: bool = False
    gateway_docker_allowed_images: str = Field(default="ubuntu:24.04,ubuntu:22.04,ubuntu:20.04")
    workspace_root: str = "./workspace"
    max_command_timeout_seconds: int = 120
    command_background_after_seconds: int = 30
    command_session_spool_root: str = "./data/command-sessions"
    max_file_read_bytes: int = 200000
    max_file_write_bytes: int = 1000000
    max_output_chars: int = 30000

    @property
    def supported_scopes(self) -> list[str]:
        return [scope for scope in self.oauth_supported_scopes.replace(",", " ").split() if scope]

    @property
    def docker_allowed_images(self) -> list[str]:
        return [image.strip() for image in self.gateway_docker_allowed_images.split(",") if image.strip()]

    @property
    def dev_roles(self) -> list[str]:
        return [role.strip() for role in self.gateway_dev_roles.split(",") if role.strip()]

    @property
    def issuer(self) -> str:
        return self.public_base_url.rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings()
