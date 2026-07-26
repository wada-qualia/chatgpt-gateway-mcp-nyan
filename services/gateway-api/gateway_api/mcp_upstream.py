from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Callable
from urllib.parse import urlencode, urlparse

import httpx
from jsonschema import Draft202012Validator, ValidationError
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import McpError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .crypto import decrypt_text, encrypt_text
from .events import emit_event
from .mcp_federation import (
    get_revision,
    get_server,
    get_tool,
    reconcile_catalog_snapshot,
)
from .mcp_federation_compat import (
    McpProtocolAdmissionError,
    admit_upstream_initialize,
)
from .mcp_federation_policy import sha256_json
from .mcp_federation_runtime import (
    EndpointResolution,
    FederationBoundaryError,
    FederationTelemetry,
    RecursionContext,
    SlidingWindowLimiter,
    assert_pinned_peer,
    new_traceparent,
    normalize_instance_id,
    resolve_endpoint,
    sanitize_untrusted,
)
from .models import (
    McpCredentialBinding,
    McpInvocation,
    McpRuntimeConnection,
    McpServer,
    McpTool,
    SecretBlob,
    utcnow,
)
from .thin_client_control import (
    ThinClientConnectionManager,
    ThinClientMcpError,
    thin_client_manager,
)

_FORBIDDEN_FORWARD_HEADERS = {
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "transfer-encoding",
}
_HEADER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,119}$")
_SECRET_KEY_PATTERN = re.compile(
    r"(?:token|secret|password|credential|authorization|cookie|private[_-]?key)", re.I
)


@dataclass(slots=True)
class CircuitState:
    failures: int = 0
    open_until_monotonic: float = 0.0
    last_error_code: str | None = None
    open_count: int = 0
    half_open_probe_active: bool = False

    @property
    def state(self) -> str:
        now = time.monotonic()
        if self.open_until_monotonic > now:
            return "open"
        if self.failures:
            return "half_open"
        return "closed"


@dataclass(slots=True)
class UpstreamCallResult:
    payload: dict[str, Any]
    truncated: bool
    serialized_bytes: int
    invocation_id: str | None = None
    is_error: bool = False


class UpstreamMcpError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        http_status: int = 502,
        unknown_outcome: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.http_status = http_status
        self.unknown_outcome = unknown_outcome

    def as_detail(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "unknown_outcome": self.unknown_outcome,
        }


class UpstreamCredentialResolver:
    def __init__(self, manager: "UpstreamMcpManager") -> None:
        self.manager = manager

    async def headers_for_server(
        self, db: Session, server: McpServer
    ) -> dict[str, str]:
        binding_id = server.credential_binding_id
        if not binding_id:
            return {}
        binding = (
            db.query(McpCredentialBinding)
            .filter(
                McpCredentialBinding.id == binding_id,
                McpCredentialBinding.owner_subject == server.owner_subject,
            )
            .first()
        )
        if binding is None or binding.status == "revoked":
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "The upstream credential binding is unavailable",
                http_status=401,
            )
        if not binding.secret_blob_id:
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "The upstream credential binding has no backend secret",
                http_status=401,
            )
        secret = (
            db.query(SecretBlob)
            .filter(
                SecretBlob.id == binding.secret_blob_id,
                SecretBlob.owner_subject == server.owner_subject,
            )
            .first()
        )
        if secret is None:
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "The upstream credential material is unavailable",
                http_status=401,
            )
        try:
            material = json.loads(decrypt_text(secret.ciphertext))
        except Exception as exc:
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "The upstream credential material cannot be decrypted",
                http_status=401,
            ) from exc
        if not isinstance(material, dict):
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "The upstream credential material is invalid",
                http_status=401,
            )
        if binding.binding_type == "oauth":
            return await self._oauth_headers(db, server, binding, material)
        if binding.binding_type == "service_account":
            return self._service_account_headers(material)
        raise UpstreamMcpError(
            "MCP_AUTH_REQUIRED",
            "Unsupported upstream credential binding type",
            http_status=401,
        )

    async def _oauth_headers(
        self,
        db: Session,
        server: McpServer,
        binding: McpCredentialBinding,
        material: dict[str, Any],
    ) -> dict[str, str]:
        audience = str(binding.audience or "")
        if not audience:
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "OAuth upstream credentials require an explicit resource audience",
                http_status=401,
            )
        self.manager.validate_resource_audience(server.endpoint_url or "", audience)
        access_token = material.get("access_token")
        expires_at = _parse_datetime(material.get("expires_at"))
        refresh_needed = not access_token or (
            expires_at is not None
            and expires_at <= datetime.now(timezone.utc) + timedelta(seconds=30)
        )
        if refresh_needed:
            material = await self._refresh_oauth_token(db, server, binding, material)
            access_token = material.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "OAuth access token is unavailable",
                http_status=401,
            )
        return {"Authorization": f"Bearer {access_token}"}

    async def _refresh_oauth_token(
        self,
        db: Session,
        server: McpServer,
        binding: McpCredentialBinding,
        material: dict[str, Any],
    ) -> dict[str, Any]:
        refresh_token = material.get("refresh_token")
        token_endpoint = material.get("token_endpoint")
        if not isinstance(refresh_token, str) or not refresh_token:
            self._mark_auth_required(db, server, binding)
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "OAuth token expired and no refresh token is available",
                http_status=401,
            )
        if not isinstance(token_endpoint, str) or not token_endpoint:
            self._mark_auth_required(db, server, binding)
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "OAuth token endpoint is unavailable",
                http_status=401,
            )
        await self.manager.validate_endpoint(token_endpoint, purpose="oauth_token")
        data: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "resource": str(binding.audience),
        }
        if binding.scopes:
            data["scope"] = " ".join(binding.scopes)
        client_id = material.get("client_id")
        client_secret = material.get("client_secret")
        if isinstance(client_id, str) and client_id:
            data["client_id"] = client_id
        auth = None
        if isinstance(client_id, str) and client_id and isinstance(client_secret, str):
            auth = httpx.BasicAuth(client_id, client_secret)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.manager.connect_timeout_seconds),
                follow_redirects=False,
            ) as client:
                response = await client.post(token_endpoint, data=data, auth=auth)
            if response.status_code in {400, 401, 403}:
                self._mark_auth_required(db, server, binding)
                raise UpstreamMcpError(
                    "MCP_AUTH_REQUIRED",
                    "OAuth token refresh was rejected",
                    http_status=401,
                )
            response.raise_for_status()
            payload = response.json()
        except UpstreamMcpError:
            raise
        except Exception as exc:
            raise UpstreamMcpError(
                "MCP_SERVER_OFFLINE",
                "OAuth token endpoint is unavailable",
                retryable=True,
            ) from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "OAuth token response did not contain an access token",
                http_status=401,
            )
        updated = dict(material)
        updated["access_token"] = token
        if isinstance(payload.get("refresh_token"), str):
            updated["refresh_token"] = payload["refresh_token"]
        expires_in = payload.get("expires_in")
        if isinstance(expires_in, (int, float)):
            updated["expires_at"] = (
                datetime.now(timezone.utc) + timedelta(seconds=float(expires_in))
            ).isoformat()
        new_secret = SecretBlob(
            id=str(uuid.uuid4()),
            owner_subject=server.owner_subject,
            kind="mcp_oauth",
            ciphertext=encrypt_text(json.dumps(updated, separators=(",", ":"))),
        )
        db.add(new_secret)
        binding.secret_blob_id = new_secret.id
        binding.status = "active"
        binding.version += 1
        binding.rotated_at = utcnow()
        binding.updated_at = utcnow()
        server.status = "discovering"
        server.version += 1
        server.updated_at = utcnow()
        db.commit()
        return updated

    @staticmethod
    def _service_account_headers(material: dict[str, Any]) -> dict[str, str]:
        mode = material.get("mode")
        if mode == "bearer":
            token = material.get("access_token")
            if not isinstance(token, str) or not token:
                raise UpstreamMcpError(
                    "MCP_AUTH_REQUIRED",
                    "Service-account bearer token is unavailable",
                    http_status=401,
                )
            return {"Authorization": f"Bearer {token}"}
        if mode == "header":
            name = material.get("header_name")
            value = material.get("header_value")
            if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
                raise UpstreamMcpError(
                    "MCP_AUTH_REQUIRED",
                    "Service-account header name is invalid",
                    http_status=401,
                )
            if name.lower() in _FORBIDDEN_FORWARD_HEADERS:
                raise UpstreamMcpError(
                    "MCP_AUTH_REQUIRED",
                    "Service-account header is not permitted",
                    http_status=401,
                )
            if not isinstance(value, str) or not value:
                raise UpstreamMcpError(
                    "MCP_AUTH_REQUIRED",
                    "Service-account header value is unavailable",
                    http_status=401,
                )
            return {name: value}
        raise UpstreamMcpError(
            "MCP_AUTH_REQUIRED",
            "Service-account credential mode is invalid",
            http_status=401,
        )

    @staticmethod
    def _mark_auth_required(
        db: Session, server: McpServer, binding: McpCredentialBinding
    ) -> None:
        binding.status = "auth_required"
        binding.updated_at = utcnow()
        server.status = "auth_required"
        server.version += 1
        server.updated_at = utcnow()
        db.commit()


class UpstreamMcpManager:
    def __init__(
        self,
        *,
        public_base_url: str,
        allow_private_networks: bool = False,
        allow_insecure_http: bool = False,
        connect_timeout_seconds: float = 10.0,
        call_timeout_seconds: float = 30.0,
        cancellation_grace_seconds: float = 3.0,
        max_concurrency_per_server: int = 4,
        max_concurrency_per_tenant: int = 16,
        calls_per_minute_per_server: int = 120,
        calls_per_minute_per_tenant: int = 600,
        max_connections: int = 32,
        max_keepalive_connections: int = 8,
        circuit_failure_threshold: int = 3,
        circuit_open_seconds: float = 30.0,
        circuit_max_open_seconds: float = 300.0,
        federation_enabled: bool = True,
        federation_writes_paused: bool = False,
        pilot_owner_subjects: set[str] | list[str] | tuple[str, ...] = (),
        gateway_instance_id: str = "gateway-local",
        max_federation_hops: int = 4,
        catalog_stale_after_seconds: int = 3600,
        max_result_bytes: int = 1_000_000,
        max_text_bytes: int = 512_000,
        max_content_items: int = 16,
        max_catalog_tools: int = 500,
        thin_client_transport: ThinClientConnectionManager | None = None,
    ) -> None:
        self.public_base_url = public_base_url.rstrip("/")
        self.allow_private_networks = allow_private_networks
        self.allow_insecure_http = allow_insecure_http
        self.connect_timeout_seconds = connect_timeout_seconds
        self.call_timeout_seconds = call_timeout_seconds
        self.cancellation_grace_seconds = cancellation_grace_seconds
        self.max_concurrency_per_server = max(1, int(max_concurrency_per_server))
        self.max_concurrency_per_tenant = max(1, int(max_concurrency_per_tenant))
        self.calls_per_minute_per_server = max(0, int(calls_per_minute_per_server))
        self.calls_per_minute_per_tenant = max(0, int(calls_per_minute_per_tenant))
        self.max_connections = max(1, int(max_connections))
        self.max_keepalive_connections = max(0, int(max_keepalive_connections))
        self.circuit_failure_threshold = max(1, int(circuit_failure_threshold))
        self.circuit_open_seconds = max(0.1, float(circuit_open_seconds))
        self.circuit_max_open_seconds = max(
            self.circuit_open_seconds, float(circuit_max_open_seconds)
        )
        self.federation_enabled = bool(federation_enabled)
        self.federation_writes_paused = bool(federation_writes_paused)
        self.pilot_owner_subjects = {
            str(subject).strip()
            for subject in pilot_owner_subjects
            if str(subject).strip()
        }
        self.gateway_instance_id = normalize_instance_id(gateway_instance_id)
        self.max_federation_hops = max(1, int(max_federation_hops))
        self.catalog_stale_after_seconds = max(1, int(catalog_stale_after_seconds))
        self.max_result_bytes = max_result_bytes
        self.max_text_bytes = max_text_bytes
        self.max_content_items = max_content_items
        self.max_catalog_tools = max(1, int(max_catalog_tools))
        self.thin_client_transport = thin_client_transport or thin_client_manager
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._tenant_semaphores: dict[str, asyncio.Semaphore] = {}
        self._circuits: dict[str, CircuitState] = {}
        self._active_calls: set[asyncio.Task[Any]] = set()
        self._server_rate = SlidingWindowLimiter()
        self._tenant_rate = SlidingWindowLimiter()
        self.telemetry = FederationTelemetry()
        self.credentials = UpstreamCredentialResolver(self)

    async def stop(self) -> None:
        tasks = list(self._active_calls)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def readiness_snapshot(self, db: Session) -> dict[str, Any]:
        servers = db.scalars(select(McpServer)).all()
        status_counts: dict[str, int] = {}
        circuit_counts: dict[str, int] = {}
        stale_catalogs = 0
        now = utcnow()
        for server in servers:
            status_counts[server.status] = status_counts.get(server.status, 0) + 1
            state = self.circuit_state(server.id)
            circuit_counts[state] = circuit_counts.get(state, 0) + 1
            refreshed = server.last_catalog_refreshed_at
            if refreshed is None or (now - refreshed).total_seconds() > self.catalog_stale_after_seconds:
                stale_catalogs += 1
        return {
            "enabled": self.federation_enabled,
            "writes_paused": self.federation_writes_paused,
            "pilot_owner_count": len(self.pilot_owner_subjects),
            "active_connections": self.telemetry.active_connections,
            "active_calls": self.telemetry.active_calls,
            "servers": status_counts,
            "circuits": circuit_counts,
            "stale_catalogs": stale_catalogs,
        }

    def prometheus_lines(self, db: Session) -> list[str]:
        snapshot = self.readiness_snapshot(db)
        lines = [
            "# TYPE gateway_mcp_servers gauge",
            "# TYPE gateway_mcp_circuits gauge",
            "# TYPE gateway_mcp_catalogs_stale gauge",
        ]
        for status, value in sorted(snapshot["servers"].items()):
            lines.append(f'gateway_mcp_servers{{status="{status}"}} {value}')
        for state, value in sorted(snapshot["circuits"].items()):
            lines.append(f'gateway_mcp_circuits{{state="{state}"}} {value}')
        lines.append(f'gateway_mcp_catalogs_stale {snapshot["stale_catalogs"]}')
        lines.extend(self.telemetry.prometheus_lines())
        return lines

    def circuit_state(self, server_id: str) -> str:
        return self._circuits.get(server_id, CircuitState()).state

    async def validate_endpoint(
        self, endpoint: str, *, purpose: str = "mcp"
    ) -> EndpointResolution:
        try:
            return await resolve_endpoint(
                endpoint,
                public_base_url=self.public_base_url,
                allow_private_networks=self.allow_private_networks,
                allow_insecure_http=self.allow_insecure_http,
            )
        except FederationBoundaryError as exc:
            raise UpstreamMcpError(
                exc.code,
                exc.message if purpose == "mcp" else f"{purpose}: {exc.message}",
                retryable=exc.code == "MCP_SERVER_OFFLINE",
                http_status=exc.http_status,
            ) from exc

    @staticmethod
    def validate_resource_audience(endpoint: str, audience: str) -> None:
        endpoint_url = urlparse(endpoint)
        audience_url = urlparse(audience)
        if audience_url.scheme not in {"http", "https"} or not audience_url.hostname:
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "OAuth resource audience must be an absolute HTTP resource URL",
                http_status=401,
            )
        endpoint_origin = (
            endpoint_url.scheme,
            (endpoint_url.hostname or "").lower(),
            endpoint_url.port or _default_port(endpoint_url.scheme),
        )
        audience_origin = (
            audience_url.scheme,
            (audience_url.hostname or "").lower(),
            audience_url.port or _default_port(audience_url.scheme),
        )
        if endpoint_origin != audience_origin:
            raise UpstreamMcpError(
                "MCP_AUTH_REQUIRED",
                "OAuth token audience does not match the upstream resource origin",
                http_status=401,
            )

    async def test_server(
        self, db: Session, *, owner_subject: str, server_id: str
    ) -> dict[str, Any]:
        server = get_server(db, owner_subject=owner_subject, server_id=server_id)
        started = time.monotonic()
        if server.origin == "thin_client":
            if (
                not server.thin_client_id
                or not server.runtime_id
                or not server.local_server_id
            ):
                raise UpstreamMcpError(
                    "MCP_PROTOCOL_MISMATCH",
                    "Thin-client MCP server identity is incomplete",
                    http_status=409,
                )
            try:
                connection = self.thin_client_transport.active_mcp_connection(
                    server.thin_client_id,
                    runtime_id=server.runtime_id,
                    local_server_id=server.local_server_id,
                )
            except ThinClientMcpError as exc:
                self._mark_failure(
                    db,
                    server,
                    UpstreamMcpError(
                        exc.code,
                        exc.message,
                        retryable=exc.retryable,
                        http_status=exc.http_status,
                    ),
                )
                raise UpstreamMcpError(
                    exc.code,
                    exc.message,
                    retryable=exc.retryable,
                    http_status=exc.http_status,
                ) from exc
            runtime = (
                db.query(McpRuntimeConnection)
                .filter(
                    McpRuntimeConnection.owner_subject == owner_subject,
                    McpRuntimeConnection.server_id == server.id,
                    McpRuntimeConnection.connection_instance_id
                    == connection.connection_instance_id,
                    McpRuntimeConnection.state == "online",
                )
                .one_or_none()
            )
            if runtime is None:
                raise UpstreamMcpError(
                    "MCP_STALE_CONNECTION",
                    "Thin-client MCP runtime evidence is stale",
                    retryable=True,
                    http_status=409,
                )
            tool_count = (
                db.query(McpTool)
                .filter(
                    McpTool.owner_subject == owner_subject,
                    McpTool.server_id == server.id,
                    McpTool.lifecycle_state == "active",
                )
                .count()
            )
            server.status = "online"
            server.last_connected_at = utcnow()
            server.updated_at = utcnow()
            db.commit()
            return {
                "server_id": server.id,
                "status": server.status,
                "trust_level": server.trust_level,
                "catalog_generation": server.catalog_generation,
                "negotiated_protocol_version": server.negotiated_protocol_version,
                "last_connected_at": server.last_connected_at,
                "last_catalog_refreshed_at": server.last_catalog_refreshed_at,
                "latency_ms": int((time.monotonic() - started) * 1000),
                "tool_count": tool_count,
                "session_id_present": True,
                "circuit_state": self.circuit_state(server.id),
                "normalized_error_code": None,
            }
        try:
            async with self._bounded(server):
                async with self._session(db, server) as (
                    session,
                    initialized,
                    session_id,
                ):
                    listed = await session.list_tools()
                    tool_count = len(listed.tools)
            self._record_success(server.id)
            self._mark_online(db, server, initialized)
            return {
                "server_id": server.id,
                "status": server.status,
                "trust_level": server.trust_level,
                "catalog_generation": server.catalog_generation,
                "negotiated_protocol_version": server.negotiated_protocol_version,
                "last_connected_at": server.last_connected_at,
                "last_catalog_refreshed_at": server.last_catalog_refreshed_at,
                "latency_ms": int((time.monotonic() - started) * 1000),
                "tool_count": tool_count,
                "session_id_present": session_id is not None,
                "circuit_state": self.circuit_state(server.id),
                "normalized_error_code": None,
            }
        except UpstreamMcpError as exc:
            self._record_failure(server.id, exc)
            self._mark_failure(db, server, exc)
            raise

    async def refresh_server(
        self,
        db: Session,
        *,
        owner_subject: str,
        actor_subject: str,
        server_id: str,
    ) -> McpServer:
        server = get_server(db, owner_subject=owner_subject, server_id=server_id)
        if server.origin == "thin_client":
            if (
                not server.thin_client_id
                or not server.runtime_id
                or not server.local_server_id
            ):
                raise UpstreamMcpError(
                    "MCP_PROTOCOL_MISMATCH",
                    "Thin-client MCP server identity is incomplete",
                    http_status=409,
                )
            try:
                connection = self.thin_client_transport.active_mcp_connection(
                    server.thin_client_id,
                    runtime_id=server.runtime_id,
                    local_server_id=server.local_server_id,
                )
                await self.thin_client_transport.send_mcp_control(
                    server.thin_client_id,
                    runtime_id=server.runtime_id,
                    local_server_id=server.local_server_id,
                    connection_instance_id=connection.connection_instance_id,
                    message={
                        "type": "mcp_refresh_catalog",
                        "reason": "operator_refresh",
                        "expected_catalog_generation": server.catalog_generation,
                    },
                )
            except ThinClientMcpError as exc:
                raise UpstreamMcpError(
                    exc.code,
                    exc.message,
                    retryable=exc.retryable,
                    http_status=exc.http_status,
                ) from exc
            server.status = "discovering"
            server.updated_at = utcnow()
            server.version += 1
            db.commit()
            return server
        generation = server.catalog_generation + 1
        tools_changed = asyncio.Event()

        async def handler(message: Any) -> None:
            if isinstance(message, types.ServerNotification) and isinstance(
                message.root, types.ToolListChangedNotification
            ):
                tools_changed.set()

        try:
            async with self._bounded(server):
                async with self._session(db, server, message_handler=handler) as (
                    session,
                    initialized,
                    _,
                ):
                    discovered: list[Any] = []
                    cursor: str | None = None
                    while True:
                        page = await session.list_tools(cursor=cursor)
                        discovered.extend(page.tools)
                        cursor = page.nextCursor
                        if not cursor:
                            break
            snapshot = [
                {
                    "upstream_name": tool.name,
                    "input_schema": dict(tool.inputSchema or {}),
                    "output_schema": dict(tool.outputSchema)
                    if tool.outputSchema
                    else None,
                    "title": tool.title,
                    "description": tool.description or "",
                    "annotations": _model_json(tool.annotations)
                    if tool.annotations
                    else {},
                }
                for tool in discovered
            ]
            try:
                reconciliation = reconcile_catalog_snapshot(
                    db,
                    owner_subject=owner_subject,
                    actor_subject=actor_subject,
                    server_id=server.id,
                    catalog_generation=generation,
                    protocol_version=initialized.protocolVersion,
                    tools=snapshot,
                    max_tools=self.max_catalog_tools,
                    tools_list_changed_seen=tools_changed.is_set(),
                )
            except Exception as exc:
                raise UpstreamMcpError(
                    "MCP_PROTOCOL_MISMATCH",
                    "Upstream MCP catalog snapshot failed validation",
                    http_status=422,
                ) from exc
            server = reconciliation["server"]
            self._record_success(server.id)
            return server
        except UpstreamMcpError as exc:
            self._record_failure(server.id, exc)
            self._mark_failure(db, server, exc)
            raise

    async def call_exact_revision(
        self,
        db: Session,
        *,
        owner_subject: str,
        actor_subject: str,
        revision_id: str,
        arguments: dict[str, Any],
        timeout_seconds: float | None = None,
        idempotency_key: str | None = None,
        gateway_tool_call_id: str | None = None,
        correlation_id: str | None = None,
        preparation_id: str | None = None,
        approval_request_id: str | None = None,
        execution_permit_id: str | None = None,
    ) -> UpstreamCallResult:
        revision = get_revision(
            db, owner_subject=owner_subject, revision_id=revision_id
        )
        tool = get_tool(db, owner_subject=owner_subject, tool_id=revision.tool_id)
        server = get_server(
            db, owner_subject=owner_subject, server_id=revision.server_id
        )
        if self.federation_writes_paused and revision.action_class in {
            "write",
            "destructive",
            "production",
        }:
            self.telemetry.increment("writes_paused_rejected", outcome=revision.action_class)
            raise UpstreamMcpError(
                "MCP_FEDERATION_WRITES_PAUSED",
                "MCP federation write actions are paused by the emergency control",
                http_status=503,
            )
        traceparent = new_traceparent()
        operation_started = time.monotonic()
        try:
            Draft202012Validator.check_schema(revision.input_schema)
            Draft202012Validator(revision.input_schema).validate(arguments)
        except ValidationError as exc:
            raise UpstreamMcpError(
                "MCP_ARGUMENT_VALIDATION_FAILED",
                f"Arguments do not match the recorded schema at {list(exc.path)}",
                http_status=422,
            ) from exc
        except Exception as exc:
            raise UpstreamMcpError(
                "MCP_PROTOCOL_MISMATCH",
                "Recorded upstream tool schema is invalid",
                http_status=409,
            ) from exc
        invocation = McpInvocation(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            actor_subject=actor_subject,
            gateway_tool_call_id=gateway_tool_call_id,
            correlation_id=correlation_id,
            server_id=server.id,
            tool_id=tool.id,
            revision_id=revision.id,
            schema_hash=revision.schema_hash,
            action_class=revision.action_class,
            arguments_redacted=_redact_structure(arguments),
            arguments_sha256=sha256_json(arguments),
            preparation_id=preparation_id,
            approval_request_id=approval_request_id,
            execution_permit_id=execution_permit_id,
            idempotency_key=idempotency_key,
            started_at=utcnow(),
            created_at=utcnow(),
        )
        db.add(invocation)
        emit_event(
            db,
            event_type="gateway.mcp.invocation.started.v1",
            actor_subject=actor_subject,
            owner_subject=owner_subject,
            action="mcp.invocation.started",
            resource_type="mcp_invocation",
            resource_id=invocation.id,
            payload={
                "invocation_id": invocation.id,
                "server_id": server.id,
                "tool_id": tool.id,
                "revision_id": revision.id,
                "schema_hash": revision.schema_hash,
                "action_class": revision.action_class,
                "traceparent": traceparent,
                "correlation_id": correlation_id,
            },
            commit=False,
        )
        db.commit()
        self.telemetry.increment("invocation_started", action_class=revision.action_class)
        try:
            async with self._bounded(server):
                if server.origin == "thin_client":
                    raw = await self._call_thin_client(
                        db,
                        server=server,
                        tool_name=tool.upstream_name,
                        revision_id=revision.id,
                        schema_hash=revision.schema_hash,
                        catalog_generation=revision.catalog_generation,
                        arguments=arguments,
                        action_class=revision.action_class,
                        timeout_seconds=timeout_seconds or self.call_timeout_seconds,
                        idempotency_key=idempotency_key,
                        invocation=invocation,
                    )
                else:
                    async with self._session(db, server) as (session, _, _):
                        current = await self._find_upstream_tool(
                            session, tool.upstream_name
                        )
                        current_hash = sha256_json(
                            {
                                "input": dict(current.inputSchema or {}),
                                "output": dict(current.outputSchema)
                                if current.outputSchema
                                else None,
                            }
                        )
                        if current_hash != revision.schema_hash:
                            raise UpstreamMcpError(
                                "MCP_TOOL_SCHEMA_CHANGED",
                                "The upstream tool schema changed after selection",
                                http_status=409,
                            )
                        raw = await self._call_with_protocol_timeout(
                            session,
                            tool.upstream_name,
                            arguments,
                            timeout_seconds or self.call_timeout_seconds,
                        )
            limited = self._limit_result(raw)
            if revision.output_schema and raw.structuredContent is not None:
                try:
                    Draft202012Validator(revision.output_schema).validate(
                        raw.structuredContent
                    )
                except ValidationError as exc:
                    raise UpstreamMcpError(
                        "MCP_PROTOCOL_MISMATCH",
                        "Upstream structured output does not match its recorded schema",
                    ) from exc
            invocation.outcome = "failed" if raw.isError else "succeeded"
            invocation.response_metadata = {
                "truncated": limited.truncated,
                "serialized_bytes": limited.serialized_bytes,
                "upstream_is_error": bool(raw.isError),
            }
            invocation.response_sha256 = sha256_json(limited.payload)
            invocation.completed_at = utcnow()
            duration_seconds = max(0.0, time.monotonic() - operation_started)
            event_type = (
                "gateway.mcp.invocation.failed.v1"
                if raw.isError
                else "gateway.mcp.invocation.completed.v1"
            )
            emit_event(
                db,
                event_type=event_type,
                actor_subject=actor_subject,
                owner_subject=owner_subject,
                action="mcp.invocation.completed",
                resource_type="mcp_invocation",
                resource_id=invocation.id,
                payload={
                    "invocation_id": invocation.id,
                    "server_id": server.id,
                    "tool_id": tool.id,
                    "revision_id": revision.id,
                    "schema_hash": revision.schema_hash,
                    "action_class": revision.action_class,
                    "outcome": invocation.outcome,
                    "duration_seconds": duration_seconds,
                    "serialized_bytes": limited.serialized_bytes,
                    "truncated": limited.truncated,
                    "traceparent": traceparent,
                    "correlation_id": correlation_id,
                },
                status="error" if raw.isError else "success",
                commit=False,
            )
            db.commit()
            self.telemetry.increment(
                "invocation_completed", outcome=invocation.outcome or "unknown"
            )
            self.telemetry.observe_latency(
                "tool_call", invocation.outcome or "unknown", duration_seconds
            )
            self._record_success(server.id)
            limited.invocation_id = invocation.id
            limited.is_error = bool(raw.isError)
            return limited
        except UpstreamMcpError as exc:
            invocation.outcome = "unknown" if exc.unknown_outcome else "failed"
            invocation.unknown_outcome = exc.unknown_outcome
            invocation.normalized_error_code = exc.code
            invocation.normalized_error_detail = exc.message[:1000]
            invocation.completed_at = utcnow()
            duration_seconds = max(0.0, time.monotonic() - operation_started)
            emit_event(
                db,
                event_type="gateway.mcp.invocation.failed.v1",
                actor_subject=actor_subject,
                owner_subject=owner_subject,
                action="mcp.invocation.failed",
                resource_type="mcp_invocation",
                resource_id=invocation.id,
                payload={
                    "invocation_id": invocation.id,
                    "server_id": server.id,
                    "tool_id": tool.id,
                    "revision_id": revision.id,
                    "schema_hash": revision.schema_hash,
                    "action_class": revision.action_class,
                    "outcome": invocation.outcome,
                    "error_code": exc.code,
                    "retryable": exc.retryable,
                    "unknown_outcome": exc.unknown_outcome,
                    "duration_seconds": duration_seconds,
                    "traceparent": traceparent,
                    "correlation_id": correlation_id,
                },
                status="error",
                commit=False,
            )
            db.commit()
            self.telemetry.increment("invocation_failed", outcome=exc.code)
            self.telemetry.observe_latency("tool_call", exc.code, duration_seconds)
            self._record_failure(server.id, exc)
            self._mark_failure(db, server, exc)
            raise

    async def _call_thin_client(
        self,
        db: Session,
        *,
        server: McpServer,
        tool_name: str,
        revision_id: str,
        schema_hash: str,
        catalog_generation: int,
        arguments: dict[str, Any],
        action_class: str,
        timeout_seconds: float,
        idempotency_key: str | None,
        invocation: McpInvocation,
    ) -> types.CallToolResult:
        if (
            not server.thin_client_id
            or not server.runtime_id
            or not server.local_server_id
        ):
            raise UpstreamMcpError(
                "MCP_PROTOCOL_MISMATCH",
                "Thin-client MCP server identity is incomplete",
                http_status=409,
            )
        try:
            connection = self.thin_client_transport.active_mcp_connection(
                server.thin_client_id,
                runtime_id=server.runtime_id,
                local_server_id=server.local_server_id,
            )
        except ThinClientMcpError as exc:
            raise UpstreamMcpError(
                exc.code,
                exc.message,
                retryable=exc.retryable,
                http_status=exc.http_status,
                unknown_outcome=exc.unknown_outcome,
            ) from exc
        runtime = (
            db.query(McpRuntimeConnection)
            .filter(
                McpRuntimeConnection.owner_subject == server.owner_subject,
                McpRuntimeConnection.server_id == server.id,
                McpRuntimeConnection.thin_client_id == server.thin_client_id,
                McpRuntimeConnection.runtime_id == server.runtime_id,
                McpRuntimeConnection.connection_instance_id
                == connection.connection_instance_id,
                McpRuntimeConnection.state == "online",
            )
            .one_or_none()
        )
        if runtime is None:
            raise UpstreamMcpError(
                "MCP_STALE_CONNECTION",
                "Thin-client MCP runtime evidence is stale",
                retryable=True,
                http_status=409,
            )
        request_id = str(uuid.uuid4())
        invocation.runtime_connection_id = runtime.id
        invocation.connection_instance_id = connection.connection_instance_id
        invocation.thin_client_request_id = request_id
        db.commit()
        try:
            response = await self.thin_client_transport.request_mcp(
                server.thin_client_id,
                runtime_id=server.runtime_id,
                local_server_id=server.local_server_id,
                connection_instance_id=connection.connection_instance_id,
                request_id=request_id,
                server_id=server.id,
                revision_id=revision_id,
                tool_name=tool_name,
                schema_hash=schema_hash,
                catalog_generation=catalog_generation,
                arguments=arguments,
                action_class=action_class,
                timeout_seconds=timeout_seconds,
                idempotency_key=idempotency_key,
            )
        except ThinClientMcpError as exc:
            raise UpstreamMcpError(
                exc.code,
                exc.message,
                retryable=exc.retryable,
                http_status=exc.http_status,
                unknown_outcome=exc.unknown_outcome,
            ) from exc
        if (
            str(response.get("schema_hash", "")) != schema_hash
            or int(response.get("catalog_generation", -1)) != catalog_generation
        ):
            raise UpstreamMcpError(
                "MCP_TOOL_SCHEMA_CHANGED",
                "Local MCP result does not match the selected catalog revision",
                http_status=409,
                unknown_outcome=action_class in {"write", "destructive", "production"},
            )
        if response.get("type") == "mcp_call_failed":
            raise UpstreamMcpError(
                str(response.get("code") or "MCP_PROTOCOL_MISMATCH")[:120],
                str(response.get("message") or "Local MCP call failed")[:500],
                retryable=bool(response.get("retryable", False)),
                unknown_outcome=bool(response.get("unknown_outcome", False)),
                http_status=int(response.get("http_status", 502)),
            )
        result = response.get("result")
        if response.get("type") != "mcp_call_result" or not isinstance(result, dict):
            raise UpstreamMcpError(
                "MCP_PROTOCOL_MISMATCH",
                "Local MCP runtime returned an invalid call result",
            )
        try:
            return types.CallToolResult.model_validate(result)
        except Exception as exc:
            raise UpstreamMcpError(
                "MCP_PROTOCOL_MISMATCH",
                "Local MCP result does not match the MCP CallToolResult contract",
            ) from exc

    async def _find_upstream_tool(self, session: ClientSession, name: str) -> Any:
        cursor: str | None = None
        while True:
            page = await session.list_tools(cursor=cursor)
            for tool in page.tools:
                if tool.name == name:
                    return tool
            cursor = page.nextCursor
            if not cursor:
                raise UpstreamMcpError(
                    "MCP_TOOL_NOT_FOUND",
                    "The upstream tool no longer exists",
                    http_status=404,
                )

    async def _call_with_protocol_timeout(
        self,
        session: ClientSession,
        name: str,
        arguments: dict[str, Any],
        timeout_seconds: float,
    ) -> types.CallToolResult:
        request_id = session._request_id
        task = asyncio.create_task(session.call_tool(name, arguments))
        self._active_calls.add(task)
        task.add_done_callback(self._active_calls.discard)
        try:
            return await asyncio.wait_for(asyncio.shield(task), timeout=timeout_seconds)
        except TimeoutError as exc:
            await session.send_notification(
                types.ClientNotification(
                    types.CancelledNotification(
                        params=types.CancelledNotificationParams(
                            requestId=request_id,
                            reason="Gateway upstream deadline exceeded",
                        )
                    )
                )
            )
            try:
                await asyncio.wait_for(task, timeout=self.cancellation_grace_seconds)
            except McpError:
                pass
            except TimeoutError:
                task.cancel()
                raise UpstreamMcpError(
                    "MCP_CALL_TIMEOUT",
                    "Upstream call timed out and cancellation was not acknowledged",
                    retryable=False,
                    unknown_outcome=True,
                    http_status=504,
                ) from exc
            except asyncio.CancelledError:
                pass
            raise UpstreamMcpError(
                "MCP_CALL_TIMEOUT",
                "Upstream call exceeded the Gateway deadline",
                retryable=False,
                http_status=504,
            ) from exc
        except asyncio.CancelledError as exc:
            if not task.done():
                await session.send_notification(
                    types.ClientNotification(
                        types.CancelledNotification(
                            params=types.CancelledNotificationParams(
                                requestId=request_id,
                                reason="Gateway caller cancelled",
                            )
                        )
                    )
                )
            raise UpstreamMcpError(
                "MCP_CALL_CANCELLED", "Upstream call was cancelled", http_status=499
            ) from exc
        except McpError as exc:
            message = str(exc.error.message)[:500]
            if "cancel" in message.lower():
                raise UpstreamMcpError(
                    "MCP_CALL_CANCELLED", "Upstream call was cancelled", http_status=499
                ) from exc
            raise UpstreamMcpError(
                "MCP_PROTOCOL_MISMATCH", "Upstream MCP call failed"
            ) from exc

    @contextlib.asynccontextmanager
    async def _session(
        self,
        db: Session,
        server: McpServer,
        *,
        message_handler: Callable[[Any], Any] | None = None,
    ) -> AsyncIterator[tuple[ClientSession, types.InitializeResult, str | None]]:
        if server.origin != "gateway" or server.transport != "streamable_http":
            raise UpstreamMcpError(
                "MCP_PROTOCOL_MISMATCH",
                "Web-added upstream runtime supports Streamable HTTP servers only",
                http_status=422,
            )
        if not server.endpoint_url:
            raise UpstreamMcpError(
                "MCP_SERVER_OFFLINE", "Upstream MCP endpoint is not configured"
            )
        resolution = await self.validate_endpoint(server.endpoint_url)
        headers = await self.credentials.headers_for_server(db, server)
        traceparent = new_traceparent()
        headers.update(
            RecursionContext(hop=0, visited=()).outbound_headers(
                self.gateway_instance_id, traceparent
            )
        )
        timeout = httpx.Timeout(
            connect=self.connect_timeout_seconds,
            read=None,
            write=self.connect_timeout_seconds,
            pool=self.connect_timeout_seconds,
        )
        limits = httpx.Limits(
            max_connections=self.max_connections,
            max_keepalive_connections=self.max_keepalive_connections,
        )

        async def validate_peer(response: httpx.Response) -> None:
            try:
                assert_pinned_peer(response, resolution)
            except FederationBoundaryError as exc:
                self.telemetry.increment("dns_rebinding_rejected", outcome=exc.code)
                raise UpstreamMcpError(
                    exc.code, exc.message, http_status=exc.http_status
                ) from exc

        connection_id = str(uuid.uuid4())
        runtime = McpRuntimeConnection(
            id=str(uuid.uuid4()),
            owner_subject=server.owner_subject,
            server_id=server.id,
            connection_instance_id=connection_id,
            supported_transports=["streamable_http"],
            supported_protocol_versions=[],
            state="connecting",
            acknowledged_catalog_generation=server.catalog_generation,
            meta={"credential_binding_configured": bool(server.credential_binding_id)},
            connected_at=utcnow(),
            last_seen_at=utcnow(),
        )
        db.add(runtime)
        db.commit()
        try:
            async with httpx.AsyncClient(
                headers=headers,
                timeout=timeout,
                limits=limits,
                follow_redirects=False,
                event_hooks={"response": [validate_peer]},
            ) as http_client:
                async with streamable_http_client(
                    server.endpoint_url,
                    http_client=http_client,
                    terminate_on_close=True,
                ) as (read_stream, write_stream, get_session_id):
                    async with ClientSession(
                        read_stream,
                        write_stream,
                        message_handler=message_handler,
                        client_info=types.Implementation(
                            name="chatgpt-mcp-federation-gateway", version="1"
                        ),
                    ) as session:
                        initialized = await session.initialize()
                        try:
                            capability_admission = admit_upstream_initialize(initialized)
                        except McpProtocolAdmissionError as exc:
                            raise UpstreamMcpError(
                                "MCP_PROTOCOL_MISMATCH",
                                str(exc),
                                http_status=422,
                            ) from exc
                        runtime.state = "online"
                        runtime.supported_protocol_versions = [
                            capability_admission.protocol_version
                        ]
                        runtime.meta = {
                            **dict(runtime.meta or {}),
                            "capability_admission": capability_admission.as_dict(),
                        }
                        runtime.last_seen_at = utcnow()
                        emit_event(
                            db,
                            event_type="gateway.mcp.runtime.connected.v1",
                            actor_subject=server.owner_subject,
                            owner_subject=server.owner_subject,
                            action="mcp.runtime.connected",
                            resource_type="mcp_runtime_connection",
                            resource_id=runtime.id,
                            payload={
                                "runtime_connection_id": runtime.id,
                                "server_id": server.id,
                                "state": "online",
                                "protocol_version": initialized.protocolVersion,
                                "traceparent": traceparent,
                            },
                            commit=False,
                        )
                        db.commit()
                        self.telemetry.active_connections += 1
                        self.telemetry.increment("runtime_connected", outcome="online")
                        try:
                            yield session, initialized, get_session_id()
                        finally:
                            self.telemetry.active_connections = max(
                                0, self.telemetry.active_connections - 1
                            )
        except UpstreamMcpError:
            runtime.state = "failed"
            runtime.disconnected_at = utcnow()
            runtime.last_seen_at = utcnow()
            db.commit()
            raise
        except httpx.HTTPStatusError as exc:
            runtime.state = "failed"
            runtime.disconnected_at = utcnow()
            runtime.last_seen_at = utcnow()
            db.commit()
            if exc.response.status_code in {401, 403}:
                raise UpstreamMcpError(
                    "MCP_AUTH_REQUIRED",
                    "Upstream MCP authorization was rejected",
                    http_status=401,
                ) from exc
            raise UpstreamMcpError(
                "MCP_SERVER_OFFLINE",
                "Upstream MCP HTTP request failed",
                retryable=exc.response.status_code >= 500,
            ) from exc
        except (httpx.HTTPError, OSError) as exc:
            runtime.state = "failed"
            runtime.disconnected_at = utcnow()
            runtime.last_seen_at = utcnow()
            db.commit()
            raise UpstreamMcpError(
                "MCP_SERVER_OFFLINE",
                "Upstream MCP server is unreachable",
                retryable=True,
            ) from exc
        except BaseExceptionGroup as exc:
            upstream_error = _find_upstream_error(exc)
            runtime.state = "failed"
            runtime.disconnected_at = utcnow()
            runtime.last_seen_at = utcnow()
            db.commit()
            if upstream_error is not None:
                raise upstream_error from exc
            raise UpstreamMcpError(
                "MCP_SERVER_OFFLINE",
                "Upstream MCP session closed with grouped transport errors",
                retryable=True,
            ) from exc
        except McpError as exc:
            runtime.state = "failed"
            runtime.disconnected_at = utcnow()
            runtime.last_seen_at = utcnow()
            db.commit()
            raise UpstreamMcpError(
                "MCP_PROTOCOL_MISMATCH", "Upstream MCP protocol negotiation failed"
            ) from exc
        except Exception as exc:
            runtime.state = "failed"
            runtime.disconnected_at = utcnow()
            runtime.last_seen_at = utcnow()
            db.commit()
            raise UpstreamMcpError(
                "MCP_SERVER_OFFLINE",
                "Upstream MCP session failed",
                retryable=True,
            ) from exc
        finally:
            if runtime.state == "online":
                runtime.state = "closed"
                runtime.disconnected_at = utcnow()
                runtime.last_seen_at = utcnow()
                emit_event(
                    db,
                    event_type="gateway.mcp.runtime.disconnected.v1",
                    actor_subject=server.owner_subject,
                    owner_subject=server.owner_subject,
                    action="mcp.runtime.disconnected",
                    resource_type="mcp_runtime_connection",
                    resource_id=runtime.id,
                    payload={
                        "runtime_connection_id": runtime.id,
                        "server_id": server.id,
                        "state": "closed",
                        "traceparent": traceparent,
                    },
                    commit=False,
                )
                db.commit()
                self.telemetry.increment("runtime_disconnected", outcome="closed")

    def federation_enabled_for(self, owner_subject: str) -> bool:
        return self.federation_enabled or owner_subject in self.pilot_owner_subjects

    @contextlib.asynccontextmanager
    async def _bounded(self, server: McpServer) -> AsyncIterator[None]:
        if not self.federation_enabled_for(server.owner_subject):
            self.telemetry.increment("emergency_disabled", outcome="rejected")
            raise UpstreamMcpError(
                "MCP_FEDERATION_DISABLED",
                "MCP federation is disabled by the emergency control",
                http_status=503,
            )
        if server.status == "disabled":
            raise UpstreamMcpError(
                "MCP_SERVER_DISABLED",
                "Upstream MCP server is disabled",
                http_status=409,
            )
        if not self._server_rate.acquire(server.id, self.calls_per_minute_per_server):
            self.telemetry.increment("quota_rejected", scope="server")
            raise UpstreamMcpError(
                "MCP_QUOTA_EXCEEDED",
                "Upstream MCP server rate quota exceeded",
                retryable=True,
                http_status=429,
            )
        tenant_key = server.owner_subject
        if not self._tenant_rate.acquire(
            tenant_key, self.calls_per_minute_per_tenant
        ):
            self.telemetry.increment("quota_rejected", scope="tenant")
            raise UpstreamMcpError(
                "MCP_QUOTA_EXCEEDED",
                "Tenant MCP federation rate quota exceeded",
                retryable=True,
                http_status=429,
            )
        circuit = self._circuits.setdefault(server.id, CircuitState())
        now = time.monotonic()
        if circuit.open_until_monotonic > now:
            self.telemetry.increment("circuit_rejected", state="open")
            raise UpstreamMcpError(
                "MCP_SERVER_OFFLINE",
                "Upstream MCP circuit is open",
                retryable=True,
                http_status=503,
            )
        half_open = bool(circuit.failures)
        if half_open and circuit.half_open_probe_active:
            self.telemetry.increment("circuit_rejected", state="half_open")
            raise UpstreamMcpError(
                "MCP_SERVER_OFFLINE",
                "Upstream MCP circuit half-open probe is already running",
                retryable=True,
                http_status=503,
            )
        if half_open:
            circuit.half_open_probe_active = True
        server_semaphore = self._semaphores.setdefault(
            server.id, asyncio.Semaphore(self.max_concurrency_per_server)
        )
        tenant_semaphore = self._tenant_semaphores.setdefault(
            tenant_key, asyncio.Semaphore(self.max_concurrency_per_tenant)
        )
        try:
            async with tenant_semaphore, server_semaphore:
                self.telemetry.active_calls += 1
                try:
                    yield
                finally:
                    self.telemetry.active_calls = max(
                        0, self.telemetry.active_calls - 1
                    )
        finally:
            if half_open:
                circuit.half_open_probe_active = False

    def _record_success(self, server_id: str) -> None:
        previous = self._circuits.get(server_id, CircuitState()).state
        self._circuits[server_id] = CircuitState()
        if previous != "closed":
            self.telemetry.increment(
                "circuit_transition", from_state=previous, to_state="closed"
            )

    def _record_failure(self, server_id: str, error: UpstreamMcpError) -> None:
        circuit = self._circuits.setdefault(server_id, CircuitState())
        previous = circuit.state
        circuit.failures += 1
        circuit.last_error_code = error.code
        circuit.half_open_probe_active = False
        if circuit.failures >= self.circuit_failure_threshold:
            circuit.open_count += 1
            delay = min(
                self.circuit_max_open_seconds,
                self.circuit_open_seconds * (2 ** max(0, circuit.open_count - 1)),
            )
            circuit.open_until_monotonic = time.monotonic() + delay
        current = circuit.state
        if current != previous:
            self.telemetry.increment(
                "circuit_transition", from_state=previous, to_state=current
            )

    def _mark_online(
        self,
        db: Session,
        server: McpServer,
        initialized: types.InitializeResult,
        *,
        commit: bool = True,
    ) -> None:
        server.status = "online"
        server.negotiated_protocol_version = initialized.protocolVersion
        server.capabilities = _model_json(initialized.capabilities)
        server.last_connected_at = utcnow()
        server.version += 1
        server.updated_at = utcnow()
        if commit:
            db.commit()
            db.refresh(server)

    @staticmethod
    def _mark_failure(db: Session, server: McpServer, error: UpstreamMcpError) -> None:
        if error.code == "MCP_SERVER_DISABLED":
            status = "disabled"
        elif error.code == "MCP_AUTH_REQUIRED":
            status = "auth_required"
        elif error.code == "MCP_SERVER_QUARANTINED":
            status = "quarantined"
        elif error.code in {"MCP_PROTOCOL_MISMATCH", "MCP_TOOL_SCHEMA_CHANGED"}:
            status = "schema_invalid"
        elif error.code == "MCP_SERVER_OFFLINE":
            status = "offline"
        else:
            status = "degraded"
        server.status = status
        server.quarantine_reason = error.code if status == "quarantined" else None
        server.version += 1
        server.updated_at = utcnow()
        db.commit()

    def _limit_result(self, result: types.CallToolResult) -> UpstreamCallResult:
        payload = sanitize_untrusted(
            result.model_dump(mode="json", by_alias=True),
            max_string=self.max_text_bytes,
        )
        if not isinstance(payload, dict):
            raise UpstreamMcpError(
                "MCP_PROTOCOL_MISMATCH",
                "Upstream MCP result is not an object",
                http_status=502,
            )
        content = payload.get("content")
        truncated = False
        if isinstance(content, list) and len(content) > self.max_content_items:
            payload["content"] = content[: self.max_content_items]
            truncated = True
        text_budget = self.max_text_bytes
        for item in payload.get("content") or []:
            if not isinstance(item, dict) or not isinstance(item.get("text"), str):
                continue
            encoded = item["text"].encode("utf-8")
            if len(encoded) <= text_budget:
                text_budget -= len(encoded)
                continue
            item["text"] = encoded[: max(text_budget, 0)].decode(
                "utf-8", errors="ignore"
            )
            item["_gateway_truncated"] = True
            text_budget = 0
            truncated = True
        serialized = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if len(serialized) > self.max_result_bytes:
            self.telemetry.increment("result_rejected", outcome="too_large")
            raise UpstreamMcpError(
                "MCP_RESULT_TOO_LARGE",
                "Upstream MCP result exceeds the Gateway result limit",
                http_status=413,
            )
        payload.setdefault("_gateway", {})["truncated"] = truncated
        if truncated:
            self.telemetry.increment("result_truncated", outcome="bounded")
        return UpstreamCallResult(
            payload=payload, truncated=truncated, serialized_bytes=len(serialized)
        )


def material_to_secret_payload(data: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "mode": data.mode,
        "access_token": _secret_value(data.access_token),
        "refresh_token": _secret_value(data.refresh_token),
        "token_endpoint": str(data.token_endpoint) if data.token_endpoint else None,
        "client_id": data.client_id,
        "client_secret": _secret_value(data.client_secret),
        "expires_at": data.expires_at.isoformat() if data.expires_at else None,
        "header_name": data.header_name,
        "header_value": _secret_value(data.header_value),
    }
    return {key: value for key, value in payload.items() if value is not None}


def build_oauth_authorization_url(
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    state: str,
    code_challenge: str,
    audience: str,
    extra: dict[str, str],
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "resource": audience,
        **extra,
    }
    return f"{authorization_endpoint}?{urlencode(params)}"


def _model_json(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True)
    if isinstance(value, dict):
        return dict(value)
    return {}


def _redact_structure(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            redacted[key] = (
                "[REDACTED]"
                if _SECRET_KEY_PATTERN.search(key)
                else _redact_structure(item)
            )
        return redacted
    if isinstance(value, list):
        return [_redact_structure(item) for item in value[:100]]
    if isinstance(value, str) and len(value) > 512:
        return value[:512] + "…"
    return value


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _secret_value(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "get_secret_value"):
        return value.get_secret_value()
    return str(value)


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _find_upstream_error(error: BaseExceptionGroup) -> UpstreamMcpError | None:
    for nested in error.exceptions:
        if isinstance(nested, UpstreamMcpError):
            return nested
        if isinstance(nested, BaseExceptionGroup):
            found = _find_upstream_error(nested)
            if found is not None:
                return found
    return None
