from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ChatGPT MCP SSH Gateway"
    gateway_release_version: str = "0.3.6"
    gateway_release_revision: str = ""
    gateway_deployment_slot: str = "local"
    public_base_url: str = "http://localhost:8000"
    database_url: str = "sqlite:///./data/gateway.db"
    gateway_db_pool_size: int = Field(default=5, ge=1, le=100)
    gateway_db_max_overflow: int = Field(default=10, ge=0, le=100)
    gateway_db_pool_timeout_seconds: float = Field(default=5.0, ge=0.1, le=60.0)
    gateway_metrics_db_pool_size: int = Field(default=1, ge=1, le=10)
    gateway_metrics_db_max_overflow: int = Field(default=0, ge=0, le=10)
    gateway_metrics_db_pool_timeout_seconds: float = Field(
        default=1.0, ge=0.1, le=30.0
    )
    gateway_storage_monitor_path: str = "./data"
    gateway_storage_warning_usage_ratio: float = Field(default=0.85, ge=0.0, le=1.0)
    gateway_storage_critical_usage_ratio: float = Field(default=0.95, ge=0.0, le=1.0)
    gateway_cold_history_enabled: bool = False
    gateway_cold_history_base_url: str = ""
    gateway_cold_history_ca_cert_path: str = ""
    gateway_cold_history_client_cert_path: str = ""
    gateway_cold_history_client_key_path: str = ""
    gateway_cold_history_connect_timeout_seconds: float = Field(
        default=2.0, ge=0.1, le=30.0
    )
    gateway_cold_history_read_timeout_seconds: float = Field(
        default=15.0, ge=0.1, le=120.0
    )
    gateway_prompt_registry_enabled: bool = False
    gateway_prompt_registry_base_url: str = "http://prompt-registry:8080"
    gateway_prompt_registry_service_token: SecretStr = SecretStr("")
    gateway_prompt_registry_connect_timeout_seconds: float = Field(
        default=2.0, ge=0.1, le=30.0
    )
    gateway_prompt_registry_read_timeout_seconds: float = Field(
        default=5.0, ge=0.1, le=60.0
    )
    gateway_prompt_registry_revalidate_after_seconds: float = Field(
        default=15.0, ge=0.0, le=300.0
    )
    gateway_prompt_registry_max_stale_seconds: int = Field(
        default=3600, ge=0, le=86400
    )
    gateway_db_migration_lock_timeout_seconds: int = 15
    gateway_db_migration_statement_timeout_seconds: int = 300
    gateway_db_online_index_timeout_seconds: int = 5400
    gateway_db_migration_advisory_lock_key: int = 1129138007
    gateway_readiness_refresh_interval_seconds: float = Field(
        default=60.0, ge=5.0, le=3600.0
    )
    gateway_readiness_max_stale_seconds: float = Field(
        default=120.0, ge=10.0, le=7200.0
    )
    gateway_readiness_probe_timeout_seconds: float = Field(
        default=1.0, ge=0.1, le=10.0
    )
    gateway_metrics_refresh_interval_seconds: float = Field(
        default=300.0, ge=10.0, le=3600.0
    )
    gateway_metrics_max_stale_seconds: float = Field(
        default=600.0, ge=30.0, le=7200.0
    )
    gateway_metrics_refresh_timeout_seconds: float = Field(
        default=30.0, ge=1.0, le=300.0
    )
    gateway_secret_key: str | None = None
    gateway_secret_key_file: str = "./data/gateway-secret.key"
    gateway_jwt_secret: str = "change-me-local-jwt-secret"
    gateway_session_cookie: str = "gateway_session"
    gateway_dev_auth: bool = True
    gateway_dev_subject: str = "dev:local"
    gateway_dev_username: str = "darius"
    gateway_dev_email: str | None = "local@example.invalid"
    gateway_dev_roles: str = "gateway-admin,gateway-user,gateway-auditor"
    gateway_access_token_ttl_seconds: int = 864000
    gateway_thin_client_token_ttl_seconds: int = 2592000
    gateway_auth_code_ttl_seconds: int = 600
    gateway_device_code_ttl_seconds: int = 900
    keycloak_issuer: str = "http://localhost:8080/realms/chatgpt-mcp"
    keycloak_client_id: str = "chatgpt-mcp-gateway"
    keycloak_client_secret: str = ""
    keycloak_ca_cert_path: str | None = None
    oauth_audience: str = "chatgpt-mcp-ssh-gateway"
    oauth_supported_scopes: str = (
        "workspace:read workspace:write workspace:exec devices:manage "
        "docker:manage audit:read usage:write usage:read chat-context:write"
    )
    gateway_browser_extension_client_id: str = "atlas-chatgpt-browser-extension"
    gateway_browser_extension_redirect_uri: str = (
        "https://cgaalfflopmcbaodnlphklclnnhmdhcn.chromiumapp.org/oauth2"
    )
    gateway_browser_extension_oauth_scopes: str = "workspace:read chat-context:write"
    gateway_browser_extension_access_token_ttl_seconds: int = Field(
        default=3600, ge=300, le=86400
    )
    gateway_chat_context_enabled: bool = False
    gateway_chat_context_ttl_seconds: int = Field(default=172800, ge=300, le=2678400)
    gateway_chat_context_renew_threshold_seconds: int = Field(
        default=43200, ge=60, le=604800
    )
    gateway_chat_context_quarantine_seconds: int = Field(
        default=604800, ge=3600, le=7776000
    )
    gateway_chat_context_allocation_attempts: int = Field(default=64, ge=1, le=512)
    gateway_chat_context_hmac_key: SecretStr = SecretStr("")
    gateway_chat_context_hmac_key_version: int = Field(default=1, ge=1, le=65535)
    gateway_mcp_federation_enabled: bool = True
    gateway_mcp_federation_writes_paused: bool = False
    gateway_mcp_federation_pilot_owner_subjects: str = ""
    gateway_mcp_instance_id: str = ""
    gateway_mcp_max_federation_hops: int = 4
    gateway_mcp_upstream_allow_private_networks: bool = False
    gateway_mcp_upstream_allow_insecure_http: bool = False
    gateway_mcp_trusted_internal_endpoints: str = ""
    gateway_mcp_upstream_connect_timeout_seconds: float = 10.0
    gateway_mcp_upstream_call_timeout_seconds: float = 30.0
    gateway_mcp_upstream_cancellation_grace_seconds: float = 3.0
    gateway_mcp_upstream_max_concurrency_per_server: int = 4
    gateway_mcp_upstream_max_concurrency_per_tenant: int = 16
    gateway_mcp_upstream_calls_per_minute_per_server: int = 120
    gateway_mcp_upstream_calls_per_minute_per_tenant: int = 600
    gateway_mcp_upstream_max_connections: int = 32
    gateway_mcp_upstream_max_keepalive_connections: int = 8
    gateway_mcp_upstream_circuit_failure_threshold: int = 3
    gateway_mcp_upstream_circuit_open_seconds: float = 30.0
    gateway_mcp_upstream_circuit_max_open_seconds: float = 300.0
    gateway_mcp_upstream_max_result_bytes: int = 1000000
    gateway_mcp_upstream_max_text_bytes: int = 512000
    gateway_mcp_upstream_max_content_items: int = 16
    gateway_mcp_catalog_max_tools: int = 500
    gateway_mcp_catalog_stale_after_seconds: int = 3600
    gateway_mcp_catalog_retrieval_max_candidates: int = 2000
    gateway_mcp_catalog_rerank_max_candidates: int = 200
    gateway_mcp_action_preparation_ttl_seconds: int = 900
    gateway_lup_enabled: bool = False
    gateway_lup_mcp_traffic_enabled: bool = False
    gateway_lup_mcp_traffic_flush_limit: int = Field(default=25, ge=1, le=250)
    gateway_lup_mcp_traffic_flush_interval_seconds: float = Field(
        default=15.0, ge=1.0, le=300.0
    )
    gateway_lup_mcp_traffic_delivery_concurrency: int = Field(
        default=4, ge=1, le=32
    )
    gateway_lup_mcp_traffic_queue_max_attempts: int = Field(
        default=10, ge=1, le=100
    )
    gateway_lup_mcp_traffic_retry_base_seconds: float = Field(
        default=5.0, ge=0.01, le=3600.0
    )
    gateway_lup_mcp_traffic_retry_max_seconds: float = Field(
        default=900.0, ge=0.01, le=86400.0
    )
    gateway_lup_endpoint: str = "stage"
    gateway_lup_timeout_seconds: float = 5.0
    gateway_lup_max_attempts: int = 3
    gateway_lup_application_token_url: str | None = None
    gateway_lup_application_client_id: str = ""
    gateway_lup_application_client_secret: SecretStr = SecretStr("")
    gateway_lup_application_scope: str = ""
    gateway_lup_project_atlas_project_key: str | None = (
        "urn:atlas:catalog:entity:products/chatgpt-mcp-ssh-gateway"
    )
    gateway_lup_project_atlas_entity_id: str | None = None
    gateway_lup_project_git_branch: str | None = None
    gateway_docker_enabled: bool = False
    gateway_docker_allowed_images: str = Field(
        default="ubuntu:24.04,ubuntu:22.04,ubuntu:20.04"
    )
    gateway_ssh_enabled: bool = True
    gateway_ssh_known_hosts_path: str = "./data/ssh/known_hosts"
    gateway_ssh_known_hosts_policy: Literal["reject", "accept-new"] = "accept-new"
    gateway_ssh_allowed_actions: str = Field(
        default="uptime,disk_usage,memory_usage,whoami,pwd,home_list"
    )
    gateway_ssh_command_profile_default: (
        Literal["restricted", "filtered", "unrestricted"] | None
    ) = None
    gateway_ssh_allow_raw_command: bool | None = None
    gateway_ssh_raw_command_max_chars: int = 8000
    gateway_agent_allow_unverified_git_context: bool = False
    gateway_replica_id: str = ""
    gateway_broker_backend: Literal["disabled", "memory", "nats"] = "disabled"
    gateway_nats_servers: str = "nats://nats:4222"
    gateway_nats_credentials_file: str = ""
    gateway_nats_nkey_seed_file: str = ""
    gateway_nats_stream: str = "GATEWAY_EVENTS"
    gateway_nats_subject_prefix: str = "gateway.events"
    gateway_nats_request_timeout_seconds: float = 15.0
    gateway_nats_publish_retry_attempts: int = 3
    gateway_nats_publish_retry_delay_seconds: float = 0.25
    gateway_outbox_enabled: bool = True
    gateway_outbox_poll_interval_seconds: float = 0.5
    gateway_outbox_batch_size: int = 100
    gateway_outbox_max_attempts: int = 10
    gateway_outbox_retry_base_seconds: float = 1.0
    gateway_outbox_retry_max_seconds: float = 300.0
    gateway_outbox_lock_ttl_seconds: int = 60
    gateway_replica_heartbeat_seconds: int = 10
    gateway_replica_ttl_seconds: int = 30
    gateway_realtime_route_ttl_seconds: int = 90
    gateway_realtime_notification_ttl_seconds: int = 86400
    gateway_autonomy_enabled: bool = False
    gateway_autonomy_emergency_stop: bool = False
    gateway_autonomy_poll_interval_seconds: float = 2.0
    gateway_autonomy_assignment_batch_size: int = 10
    gateway_autonomy_approval_ttl_seconds: int = 3600
    gateway_autonomy_permit_ttl_seconds: int = 300
    gateway_affine_approval_projection_enabled: bool = False
    gateway_affine_approval_server_endpoint: str = (
        "http://affine-research-provider:8010/mcp"
    )
    gateway_affine_approval_preview_max_chars: int = 1200
    gateway_affine_approval_preview_max_items: int = 20
    gateway_affine_approval_reviewer_max_subjects: int = 100
    gateway_affine_approval_reviewer_map_json: str = "{}"
    gateway_affine_approval_vote_bridge_enabled: bool = False
    gateway_affine_approval_public_key_files: str = ""
    gateway_affine_approval_assertion_ttl_seconds: int = Field(default=60, ge=10, le=300)
    gateway_affine_approval_assertion_clock_skew_seconds: int = Field(default=15, ge=0, le=120)
    gateway_research_persistent_writes_enabled: bool = False
    gateway_research_unattended_approval_enabled: bool = False
    gateway_research_unattended_approver_subject: str = ""
    gateway_research_unattended_allowed_server_ids: str = ""
    gateway_research_unattended_allowed_tools: str = ""
    gateway_research_unattended_poll_interval_seconds: float = 2.0
    gateway_research_unattended_batch_size: int = 25
    gateway_ssh_raw_command_denied_patterns: str = Field(
        default="sudo\\b,su\\b,reboot\\b,shutdown\\b,mkfs\\b,mount\\b,umount\\b,chmod\\s+-R,chown\\s+-R,>\\s*/dev/"
    )
    workspace_root: str = "./workspace"
    max_command_timeout_seconds: int = 120
    command_background_after_seconds: int = 30
    command_session_spool_root: str = "./data/command-sessions"
    max_file_read_bytes: int = 200000
    max_file_write_bytes: int = 1000000
    max_output_chars: int = 30000

    @model_validator(mode="after")
    def validate_chat_context_settings(self) -> Settings:
        if (
            self.gateway_chat_context_renew_threshold_seconds
            >= self.gateway_chat_context_ttl_seconds
        ):
            raise ValueError(
                "gateway_chat_context_renew_threshold_seconds must be lower than "
                "gateway_chat_context_ttl_seconds"
            )
        if self.gateway_chat_context_enabled:
            key = self.gateway_chat_context_hmac_key.get_secret_value().encode("utf-8")
            if len(key) < 32:
                raise ValueError(
                    "gateway_chat_context_hmac_key must contain at least 32 bytes "
                    "when chat context is enabled"
                )
        return self

    @property
    def nats_servers(self) -> list[str]:
        return [
            value.strip()
            for value in self.gateway_nats_servers.split(",")
            if value.strip()
        ]

    @property
    def mcp_federation_pilot_owner_subjects(self) -> set[str]:
        return {
            subject.strip()
            for subject in self.gateway_mcp_federation_pilot_owner_subjects.split(",")
            if subject.strip()
        }

    @property
    def mcp_trusted_internal_endpoints(self) -> set[str]:
        return {
            endpoint.strip()
            for endpoint in self.gateway_mcp_trusted_internal_endpoints.split(",")
            if endpoint.strip()
        }

    @property
    def supported_scopes(self) -> list[str]:
        return [
            scope
            for scope in self.oauth_supported_scopes.replace(",", " ").split()
            if scope
        ]

    @property
    def docker_allowed_images(self) -> list[str]:
        return [
            image.strip()
            for image in self.gateway_docker_allowed_images.split(",")
            if image.strip()
        ]

    @property
    def ssh_allowed_actions(self) -> list[str]:
        return [
            action.strip()
            for action in self.gateway_ssh_allowed_actions.split(",")
            if action.strip()
        ]

    @property
    def ssh_command_profile_default(
        self,
    ) -> Literal["restricted", "filtered", "unrestricted"]:
        if self.gateway_ssh_command_profile_default is not None:
            return self.gateway_ssh_command_profile_default
        if self.gateway_ssh_allow_raw_command is True:
            return "filtered"
        if self.gateway_ssh_allow_raw_command is False:
            return "restricted"
        return "unrestricted"

    @property
    def ssh_raw_command_denied_patterns(self) -> list[str]:
        return [
            pattern.strip()
            for pattern in self.gateway_ssh_raw_command_denied_patterns.split(",")
            if pattern.strip()
        ]

    @property
    def dev_roles(self) -> list[str]:
        return [
            role.strip() for role in self.gateway_dev_roles.split(",") if role.strip()
        ]

    @property
    def issuer(self) -> str:
        return self.public_base_url.rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings()
