from __future__ import annotations

import re
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .mcp_capability_control_plane import record_capability_snapshot
from .mcp_federation import reconcile_catalog_snapshot
from .mcp_federation_policy import normalize_slug, sha256_json
from .models import (
    McpInvocation,
    McpRuntimeConnection,
    McpServer,
    McpTool,
    McpToolRevision,
    ThinClient,
    utcnow,
)
from .thin_client_control import (
    MCP_THIN_CLIENT_CAPABILITIES,
    MCP_THIN_CLIENT_PROTOCOL_VERSION,
    ThinClientConnection,
    ThinClientMcpError,
)

_LOCAL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_RUNTIME_NAMESPACE = uuid.UUID("ee7273be-70ec-4c98-9dbf-05b0ab4e2df2")
_ALLOWED_TRANSPORTS = {"stdio", "streamable_http", "private_http"}
_ALLOWED_SERVER_STATES = {"online", "degraded", "offline", "failed", "restarting"}


def _required_identifier(message: dict[str, Any], name: str) -> str:
    value = str(message.get(name, "")).strip()
    if not _LOCAL_ID.fullmatch(value):
        raise ThinClientMcpError(
            "MCP_PROTOCOL_MISMATCH",
            f"Invalid or missing {name}",
            http_status=422,
        )
    return value


def _server_identity(
    owner_subject: str, client_id: str, runtime_id: str, local_server_id: str
) -> str:
    return str(
        uuid.uuid5(
            _RUNTIME_NAMESPACE,
            f"{owner_subject}\n{client_id}\n{runtime_id}\n{local_server_id}",
        )
    )


def _runtime_connection(
    db: Session,
    *,
    owner_subject: str,
    server_id: str,
    client_id: str,
    runtime_id: str,
    connection_instance_id: str,
) -> McpRuntimeConnection:
    runtime = (
        db.query(McpRuntimeConnection)
        .filter(
            McpRuntimeConnection.owner_subject == owner_subject,
            McpRuntimeConnection.server_id == server_id,
            McpRuntimeConnection.thin_client_id == client_id,
            McpRuntimeConnection.runtime_id == runtime_id,
            McpRuntimeConnection.connection_instance_id == connection_instance_id,
            McpRuntimeConnection.state == "online",
        )
        .one_or_none()
    )
    if runtime is None:
        raise ThinClientMcpError(
            "MCP_STALE_CONNECTION",
            "The local MCP connection instance is stale or unregistered",
            retryable=True,
            http_status=409,
        )
    return runtime


def register_runtime(
    db: Session,
    *,
    owner_subject: str,
    client_id: str,
    connection: ThinClientConnection,
    message: dict[str, Any],
) -> dict[str, Any]:
    runtime_id = _required_identifier(message, "runtime_id")
    protocol_version = str(message.get("protocol_version", ""))
    raw_capabilities = message.get("capabilities")
    capabilities = (
        {str(item) for item in raw_capabilities if isinstance(item, str)}
        if isinstance(raw_capabilities, list)
        else set()
    )
    raw_servers = message.get("servers")
    if not isinstance(raw_servers, list) or len(raw_servers) > 100:
        raise ThinClientMcpError(
            "MCP_PROTOCOL_MISMATCH",
            "Thin-client runtime servers must be a bounded list",
            http_status=422,
        )

    client = (
        db.query(ThinClient)
        .filter(
            ThinClient.id == client_id,
            ThinClient.owner_subject == owner_subject,
        )
        .one_or_none()
    )
    if client is None:
        raise ThinClientMcpError("MCP_SERVER_OFFLINE", "Thin client not found")

    descriptors: list[dict[str, str]] = []
    local_server_ids: set[str] = set()
    for raw in raw_servers:
        if not isinstance(raw, dict):
            raise ThinClientMcpError(
                "MCP_PROTOCOL_MISMATCH", "Invalid local MCP server descriptor"
            )
        local_server_id = _required_identifier(raw, "local_server_id")
        if local_server_id in local_server_ids:
            raise ThinClientMcpError(
                "MCP_PROTOCOL_MISMATCH", "Duplicate local MCP server id"
            )
        local_server_ids.add(local_server_id)
        transport = str(raw.get("transport", ""))
        if transport not in _ALLOWED_TRANSPORTS:
            raise ThinClientMcpError(
                "MCP_PROTOCOL_MISMATCH",
                "Unsupported local MCP transport",
                http_status=422,
            )
        display_name = " ".join(
            str(raw.get("display_name") or local_server_id).split()
        )[:180]
        descriptors.append(
            {
                "local_server_id": local_server_id,
                "transport": transport,
                "display_name": display_name,
            }
        )

    # Negotiation mutates only the in-memory connection after all descriptors validate.
    # The coroutine is deliberately driven by the websocket router before this sync
    # persistence function is called.
    if connection.runtime_id != runtime_id:
        raise ThinClientMcpError(
            "MCP_STALE_CONNECTION",
            "Runtime registration was not negotiated for this connection",
        )

    mappings: list[dict[str, Any]] = []
    now = utcnow()
    for descriptor in descriptors:
        local_server_id = descriptor["local_server_id"]
        server_id = _server_identity(
            owner_subject, client_id, runtime_id, local_server_id
        )
        server = db.get(McpServer, server_id)
        if server is not None and (
            server.owner_subject != owner_subject
            or server.thin_client_id != client_id
            or server.runtime_id != runtime_id
            or server.local_server_id != local_server_id
        ):
            raise ThinClientMcpError(
                "MCP_CROSS_TENANT_REFERENCE",
                "Local MCP server identity collision",
                http_status=403,
            )
        if server is None:
            slug_base = normalize_slug(
                f"{descriptor['display_name']}-{local_server_id}"
            )[:105]
            server = McpServer(
                id=server_id,
                owner_subject=owner_subject,
                origin="thin_client",
                thin_client_id=client_id,
                runtime_id=runtime_id,
                local_server_id=local_server_id,
                display_name=descriptor["display_name"],
                normalized_slug=f"{slug_base}-{server_id[:8]}",
                transport=descriptor["transport"],
                endpoint_url=None,
                status="discovering",
                trust_level="unreviewed",
                capabilities={
                    "thin_client_protocol": protocol_version,
                    "runtime_capabilities": sorted(
                        capabilities.intersection(MCP_THIN_CLIENT_CAPABILITIES)
                    ),
                },
                catalog_generation=0,
                policy_generation=1,
                version=1,
                created_at=now,
                updated_at=now,
            )
            db.add(server)
            # McpRuntimeConnection references this deterministic server id, but the
            # models intentionally do not expose an ORM relationship that SQLAlchemy
            # can use to order the inserts. Persist the parent row before creating the
            # dependent runtime row so PostgreSQL cannot observe a transient FK gap.
            db.flush([server])
        else:
            if server.transport != descriptor["transport"]:
                server.trust_level = "unreviewed"
                server.quarantine_reason = (
                    "Local MCP transport changed and requires review"
                )
            server.display_name = descriptor["display_name"]
            server.transport = descriptor["transport"]
            server.status = "discovering"
            server.updated_at = now
            server.version += 1
            capabilities_value = dict(server.capabilities or {})
            capabilities_value.update(
                {
                    "thin_client_protocol": protocol_version,
                    "runtime_capabilities": sorted(
                        capabilities.intersection(MCP_THIN_CLIENT_CAPABILITIES)
                    ),
                }
            )
            server.capabilities = capabilities_value

        stale = (
            db.query(McpRuntimeConnection)
            .filter(
                McpRuntimeConnection.owner_subject == owner_subject,
                McpRuntimeConnection.server_id == server_id,
                McpRuntimeConnection.state.in_(["connecting", "online"]),
                McpRuntimeConnection.connection_instance_id
                != connection.connection_instance_id,
            )
            .all()
        )
        for previous in stale:
            previous.state = "stale"
            previous.disconnected_at = now
            previous.last_seen_at = now

        runtime = (
            db.query(McpRuntimeConnection)
            .filter(
                McpRuntimeConnection.owner_subject == owner_subject,
                McpRuntimeConnection.server_id == server_id,
                McpRuntimeConnection.connection_instance_id
                == connection.connection_instance_id,
            )
            .one_or_none()
        )
        if runtime is None:
            runtime = McpRuntimeConnection(
                id=str(uuid.uuid4()),
                owner_subject=owner_subject,
                server_id=server_id,
                thin_client_id=client_id,
                runtime_id=runtime_id,
                connection_instance_id=connection.connection_instance_id,
                supported_transports=[descriptor["transport"]],
                supported_protocol_versions=[protocol_version],
                state="online",
                acknowledged_catalog_generation=server.catalog_generation,
                meta={
                    "local_server_id": local_server_id,
                    "capabilities": sorted(
                        capabilities.intersection(MCP_THIN_CLIENT_CAPABILITIES)
                    ),
                },
                connected_at=now,
                last_seen_at=now,
            )
            db.add(runtime)
        else:
            runtime.state = "online"
            runtime.last_seen_at = now
            runtime.disconnected_at = None

        db.flush([runtime])
        record_capability_snapshot(
            db,
            owner_subject=owner_subject,
            server_id=server_id,
            runtime_connection_id=runtime.id,
            source="thin_client_registration",
            protocol_version=protocol_version,
            catalog_generation=server.catalog_generation,
            server_capabilities={"tools": {"catalog": True}},
            client_capabilities={},
            negotiated_features={
                "thin_client_protocol": MCP_THIN_CLIENT_PROTOCOL_VERSION,
                "runtime_capabilities": sorted(
                    capabilities.intersection(MCP_THIN_CLIENT_CAPABILITIES)
                ),
                "transport": descriptor["transport"],
            },
        )
        server.last_connected_at = now
        mappings.append(
            {
                "local_server_id": local_server_id,
                "server_id": server_id,
                "gateway_catalog_generation": server.catalog_generation,
            }
        )

    client.status = "online"
    client.last_seen_at = now
    meta = dict(client.meta or {})
    meta["mcp_runtime"] = {
        "runtime_id": runtime_id,
        "protocol_version": protocol_version,
        "connection_instance_id": connection.connection_instance_id,
        "capabilities": sorted(capabilities.intersection(MCP_THIN_CLIENT_CAPABILITIES)),
        "local_server_count": len(mappings),
    }
    client.meta = meta
    db.commit()
    return {
        "type": "mcp_runtime_registered_ack",
        "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
        "connection_instance_id": connection.connection_instance_id,
        "runtime_id": runtime_id,
        "servers": mappings,
    }


def _resolve_server(
    db: Session,
    *,
    owner_subject: str,
    client_id: str,
    runtime_id: str,
    local_server_id: str,
) -> McpServer:
    server = (
        db.query(McpServer)
        .filter(
            McpServer.owner_subject == owner_subject,
            McpServer.origin == "thin_client",
            McpServer.thin_client_id == client_id,
            McpServer.runtime_id == runtime_id,
            McpServer.local_server_id == local_server_id,
        )
        .one_or_none()
    )
    if server is None:
        raise ThinClientMcpError(
            "MCP_SERVER_OFFLINE", "Local MCP server is not registered", http_status=404
        )
    return server


def reconcile_snapshot(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    client_id: str,
    connection: ThinClientConnection,
    message: dict[str, Any],
    max_tools: int,
) -> dict[str, Any]:
    runtime_id = _required_identifier(message, "runtime_id")
    local_server_id = _required_identifier(message, "local_server_id")
    if (
        runtime_id != connection.runtime_id
        or str(message.get("connection_instance_id", ""))
        != connection.connection_instance_id
    ):
        raise ThinClientMcpError(
            "MCP_STALE_CONNECTION", "Catalog snapshot came from a stale connection"
        )
    tools = message.get("tools")
    if not isinstance(tools, list):
        raise ThinClientMcpError(
            "MCP_PROTOCOL_MISMATCH", "Catalog snapshot tools must be a list"
        )
    client_generation = int(message.get("catalog_generation", 0))
    if client_generation < 1:
        raise ThinClientMcpError(
            "MCP_PROTOCOL_MISMATCH", "Catalog generation must be positive"
        )
    server = _resolve_server(
        db,
        owner_subject=owner_subject,
        client_id=client_id,
        runtime_id=runtime_id,
        local_server_id=local_server_id,
    )
    runtime = _runtime_connection(
        db,
        owner_subject=owner_subject,
        server_id=server.id,
        client_id=client_id,
        runtime_id=runtime_id,
        connection_instance_id=connection.connection_instance_id,
    )
    snapshot_hash = sha256_json(tools)
    runtime_meta = dict(runtime.meta or {})
    if (
        runtime_meta.get("client_catalog_generation") == client_generation
        and runtime_meta.get("snapshot_sha256") == snapshot_hash
    ):
        runtime.last_seen_at = utcnow()
        db.commit()
        return {
            "type": "mcp_catalog_ack",
            "connection_instance_id": connection.connection_instance_id,
            "runtime_id": runtime_id,
            "local_server_id": local_server_id,
            "client_catalog_generation": client_generation,
            "gateway_catalog_generation": server.catalog_generation,
            "unchanged": True,
        }

    try:
        reconciliation = reconcile_catalog_snapshot(
            db,
            owner_subject=owner_subject,
            actor_subject=actor_subject,
            server_id=server.id,
            catalog_generation=server.catalog_generation + 1,
            protocol_version=str(message.get("mcp_protocol_version") or "2025-11-25"),
            tools=tools,
            max_tools=max_tools,
            tools_list_changed_seen=bool(message.get("tools_list_changed_seen", False)),
        )
    except HTTPException as exc:
        db.rollback()
        raise ThinClientMcpError(
            "MCP_PROTOCOL_MISMATCH",
            str(exc.detail)[:500],
            http_status=exc.status_code,
        ) from exc
    server = reconciliation["server"]
    runtime = db.get(McpRuntimeConnection, runtime.id)
    if runtime is None:
        raise ThinClientMcpError(
            "MCP_STALE_CONNECTION",
            "Runtime connection disappeared during reconciliation",
        )
    runtime.acknowledged_catalog_generation = server.catalog_generation
    runtime.last_seen_at = utcnow()
    runtime_meta.update(
        {
            "local_server_id": local_server_id,
            "client_catalog_generation": client_generation,
            "snapshot_sha256": snapshot_hash,
        }
    )
    runtime.meta = runtime_meta
    db.commit()
    return {
        "type": "mcp_catalog_ack",
        "connection_instance_id": connection.connection_instance_id,
        "runtime_id": runtime_id,
        "local_server_id": local_server_id,
        "client_catalog_generation": client_generation,
        "gateway_catalog_generation": server.catalog_generation,
        "unchanged": False,
        "tool_count": reconciliation["tool_count"],
        "created_revision_count": reconciliation["created_revision_count"],
        "missing_tool_count": reconciliation["missing_tool_count"],
    }


def _current_snapshot(db: Session, server: McpServer) -> dict[str, dict[str, Any]]:
    items: dict[str, dict[str, Any]] = {}
    tools = (
        db.query(McpTool)
        .filter(
            McpTool.owner_subject == server.owner_subject,
            McpTool.server_id == server.id,
            McpTool.lifecycle_state == "active",
        )
        .all()
    )
    for tool in tools:
        if not tool.current_revision_id:
            continue
        revision = db.get(McpToolRevision, tool.current_revision_id)
        if revision is None:
            continue
        items[tool.upstream_name] = {
            "upstream_name": tool.upstream_name,
            "input_schema": dict(revision.input_schema or {}),
            "output_schema": dict(revision.output_schema)
            if revision.output_schema
            else None,
            "title": revision.sanitized_title,
            "description": revision.sanitized_description,
            "annotations": dict(revision.annotations or {}),
        }
    return items


def reconcile_delta(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    client_id: str,
    connection: ThinClientConnection,
    message: dict[str, Any],
    max_tools: int,
) -> dict[str, Any]:
    runtime_id = _required_identifier(message, "runtime_id")
    local_server_id = _required_identifier(message, "local_server_id")
    server = _resolve_server(
        db,
        owner_subject=owner_subject,
        client_id=client_id,
        runtime_id=runtime_id,
        local_server_id=local_server_id,
    )
    runtime = _runtime_connection(
        db,
        owner_subject=owner_subject,
        server_id=server.id,
        client_id=client_id,
        runtime_id=runtime_id,
        connection_instance_id=connection.connection_instance_id,
    )
    runtime_meta = dict(runtime.meta or {})
    base_generation = int(message.get("base_catalog_generation", 0))
    expected = int(runtime_meta.get("client_catalog_generation", 0))
    if base_generation != expected:
        return {
            "type": "mcp_refresh_catalog",
            "connection_instance_id": connection.connection_instance_id,
            "runtime_id": runtime_id,
            "local_server_id": local_server_id,
            "reason": "catalog_generation_mismatch",
            "expected_catalog_generation": expected,
        }
    snapshot = _current_snapshot(db, server)
    changed = message.get("tools")
    removed = message.get("removed_tools", [])
    if not isinstance(changed, list) or not isinstance(removed, list):
        raise ThinClientMcpError(
            "MCP_PROTOCOL_MISMATCH", "Invalid catalog delta payload"
        )
    for item in changed:
        if not isinstance(item, dict):
            raise ThinClientMcpError(
                "MCP_PROTOCOL_MISMATCH", "Invalid catalog delta tool"
            )
        name = str(item.get("upstream_name", ""))
        if not name:
            raise ThinClientMcpError(
                "MCP_PROTOCOL_MISMATCH", "Catalog delta tool name is required"
            )
        snapshot[name] = item
    for name in removed:
        snapshot.pop(str(name), None)
    snapshot_message = {
        **message,
        "type": "mcp_catalog_snapshot",
        "catalog_generation": int(
            message.get("catalog_generation", base_generation + 1)
        ),
        "tools": list(snapshot.values()),
        "tools_list_changed_seen": True,
    }
    return reconcile_snapshot(
        db,
        owner_subject=owner_subject,
        actor_subject=actor_subject,
        client_id=client_id,
        connection=connection,
        message=snapshot_message,
        max_tools=max_tools,
    )


def record_server_status(
    db: Session,
    *,
    owner_subject: str,
    client_id: str,
    connection: ThinClientConnection,
    message: dict[str, Any],
) -> None:
    runtime_id = _required_identifier(message, "runtime_id")
    local_server_id = _required_identifier(message, "local_server_id")
    state = str(message.get("status", ""))
    if state not in _ALLOWED_SERVER_STATES:
        raise ThinClientMcpError("MCP_PROTOCOL_MISMATCH", "Invalid MCP server status")
    server = _resolve_server(
        db,
        owner_subject=owner_subject,
        client_id=client_id,
        runtime_id=runtime_id,
        local_server_id=local_server_id,
    )
    runtime = _runtime_connection(
        db,
        owner_subject=owner_subject,
        server_id=server.id,
        client_id=client_id,
        runtime_id=runtime_id,
        connection_instance_id=connection.connection_instance_id,
    )
    runtime.state = "online" if state in {"online", "degraded"} else state
    runtime.last_seen_at = utcnow()
    meta = dict(runtime.meta or {})
    meta["local_status"] = state
    if message.get("error_code"):
        meta["error_code"] = str(message["error_code"])[:120]
    runtime.meta = meta
    server.status = "degraded" if state in {"failed", "degraded"} else state
    server.updated_at = utcnow()
    db.commit()


def record_call_progress(
    db: Session,
    *,
    owner_subject: str,
    connection: ThinClientConnection,
    message: dict[str, Any],
) -> None:
    request_id = str(message.get("request_id", ""))
    invocation = (
        db.query(McpInvocation)
        .filter(
            McpInvocation.owner_subject == owner_subject,
            McpInvocation.thin_client_request_id == request_id,
            McpInvocation.connection_instance_id == connection.connection_instance_id,
            McpInvocation.outcome == "running",
        )
        .one_or_none()
    )
    if invocation is None:
        return
    metadata = dict(invocation.response_metadata or {})
    metadata["last_progress"] = {
        "progress": message.get("progress"),
        "total": message.get("total"),
        "message": str(message.get("message", ""))[:500],
        "observed_at": utcnow().isoformat(),
    }
    invocation.response_metadata = metadata
    db.commit()


def mark_connection_disconnected(
    db: Session,
    *,
    owner_subject: str,
    client_id: str,
    connection: ThinClientConnection,
) -> None:
    if not connection.runtime_id:
        return
    now = utcnow()
    runtimes = (
        db.query(McpRuntimeConnection)
        .filter(
            McpRuntimeConnection.owner_subject == owner_subject,
            McpRuntimeConnection.thin_client_id == client_id,
            McpRuntimeConnection.runtime_id == connection.runtime_id,
            McpRuntimeConnection.connection_instance_id
            == connection.connection_instance_id,
            McpRuntimeConnection.state.in_(["connecting", "online", "restarting"]),
        )
        .all()
    )
    server_ids = {runtime.server_id for runtime in runtimes}
    for runtime in runtimes:
        runtime.state = "offline"
        runtime.disconnected_at = now
        runtime.last_seen_at = now
    for server_id in server_ids:
        another_online = (
            db.query(McpRuntimeConnection.id)
            .filter(
                McpRuntimeConnection.server_id == server_id,
                McpRuntimeConnection.connection_instance_id
                != connection.connection_instance_id,
                McpRuntimeConnection.state == "online",
            )
            .first()
        )
        if another_online is None:
            server = db.get(McpServer, server_id)
            if server is not None:
                server.status = "offline"
                server.updated_at = now
    invocations = (
        db.query(McpInvocation)
        .filter(
            McpInvocation.owner_subject == owner_subject,
            McpInvocation.connection_instance_id == connection.connection_instance_id,
            McpInvocation.outcome == "running",
        )
        .all()
    )
    for invocation in invocations:
        is_write = invocation.action_class in {"write", "destructive", "production"}
        invocation.outcome = "unknown" if is_write else "failed"
        invocation.unknown_outcome = is_write
        invocation.normalized_error_code = "MCP_CONNECTION_LOST"
        invocation.normalized_error_detail = (
            "Thin-client connection was lost after the local MCP call was dispatched"
        )
        invocation.completed_at = now
    db.commit()


def protocol_error_payload(exc: ThinClientMcpError) -> dict[str, Any]:
    return {
        "type": "mcp_protocol_error",
        "code": exc.code,
        "message": exc.message,
        "unknown_outcome": exc.unknown_outcome,
        "retryable": exc.retryable,
    }


def ensure_exact_connection_message(
    connection: ThinClientConnection, message: dict[str, Any]
) -> None:
    if (
        str(message.get("connection_instance_id", ""))
        != connection.connection_instance_id
    ):
        raise ThinClientMcpError(
            "MCP_STALE_CONNECTION", "Message connection_instance_id is stale"
        )
    if (
        connection.runtime_id
        and str(message.get("runtime_id", "")) != connection.runtime_id
    ):
        raise ThinClientMcpError("MCP_STALE_CONNECTION", "Message runtime_id is stale")


def http_exception(exc: ThinClientMcpError) -> HTTPException:
    return HTTPException(status_code=exc.http_status, detail=exc.message)
