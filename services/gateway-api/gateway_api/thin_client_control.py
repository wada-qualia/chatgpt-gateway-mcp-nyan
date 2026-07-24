from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, WebSocket, status


MCP_THIN_CLIENT_PROTOCOL_VERSION = "1.0"
MCP_THIN_CLIENT_CAPABILITIES = frozenset(
    {
        "mcp_runtime_v1",
        "mcp_catalog_snapshot",
        "mcp_catalog_delta",
        "mcp_call",
        "mcp_cancel",
        "mcp_progress",
        "mcp_unknown_outcome",
    }
)


class ThinClientMcpError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        unknown_outcome: bool = False,
        retryable: bool = False,
        http_status: int = 409,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.unknown_outcome = unknown_outcome
        self.retryable = retryable
        self.http_status = http_status


@dataclass
class ThinClientConnection:
    websocket: WebSocket
    connection_instance_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    runtime_id: str | None = None
    protocol_version: str | None = None
    capabilities: frozenset[str] = field(default_factory=frozenset)
    local_server_ids: frozenset[str] = field(default_factory=frozenset)
    stale: bool = False


@dataclass
class PendingThinClientRequest:
    client_id: str
    connection: ThinClientConnection
    future: asyncio.Future[dict[str, Any]]
    kind: str
    runtime_id: str | None = None
    local_server_id: str | None = None
    action_class: str = "read"
    dispatched: bool = False

    @property
    def unknown_if_interrupted(self) -> bool:
        return self.dispatched and self.action_class in {
            "write",
            "destructive",
            "production",
        }


class ThinClientConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, list[ThinClientConnection]] = {}
        self._pending: dict[str, PendingThinClientRequest] = {}

    async def register(
        self, client_id: str, websocket: WebSocket
    ) -> ThinClientConnection:
        connection = ThinClientConnection(websocket=websocket)
        self._connections.setdefault(client_id, []).append(connection)
        return connection

    async def register_runtime(
        self,
        client_id: str,
        connection: ThinClientConnection,
        *,
        runtime_id: str,
        protocol_version: str,
        capabilities: set[str] | frozenset[str],
        local_server_ids: set[str] | frozenset[str],
    ) -> list[ThinClientConnection]:
        if connection not in self._connections.get(client_id, []):
            raise ThinClientMcpError(
                "MCP_STALE_CONNECTION",
                "Thin-client connection is no longer active",
                http_status=409,
            )
        if protocol_version != MCP_THIN_CLIENT_PROTOCOL_VERSION:
            raise ThinClientMcpError(
                "MCP_PROTOCOL_MISMATCH",
                "Unsupported thin-client MCP protocol version",
                http_status=422,
            )
        negotiated = frozenset(capabilities).intersection(MCP_THIN_CLIENT_CAPABILITIES)
        if "mcp_runtime_v1" not in negotiated:
            raise ThinClientMcpError(
                "MCP_PROTOCOL_MISMATCH",
                "Thin client did not negotiate mcp_runtime_v1",
                http_status=422,
            )

        stale_connections: list[ThinClientConnection] = []
        for candidate in self._connections.get(client_id, []):
            if candidate is connection or candidate.runtime_id != runtime_id:
                continue
            candidate.stale = True
            stale_connections.append(candidate)
            self._fail_pending_for_connection(
                client_id,
                candidate,
                code="MCP_STALE_CONNECTION",
                message="A newer connection instance replaced this MCP runtime",
            )

        connection.runtime_id = runtime_id
        connection.protocol_version = protocol_version
        connection.capabilities = negotiated
        connection.local_server_ids = frozenset(local_server_ids)
        connection.stale = False
        return stale_connections

    def is_connected(self, client_id: str) -> bool:
        return any(
            not connection.stale for connection in self._connections.get(client_id, [])
        )

    def active_mcp_connection(
        self,
        client_id: str,
        *,
        runtime_id: str,
        local_server_id: str,
    ) -> ThinClientConnection:
        for connection in reversed(self._connections.get(client_id, [])):
            if (
                not connection.stale
                and connection.runtime_id == runtime_id
                and local_server_id in connection.local_server_ids
                and "mcp_runtime_v1" in connection.capabilities
            ):
                return connection
        raise ThinClientMcpError(
            "MCP_SERVER_OFFLINE",
            "The selected local MCP runtime is not connected",
            retryable=True,
            http_status=409,
        )

    async def unregister(
        self,
        client_id: str,
        connection: ThinClientConnection | None = None,
    ) -> bool:
        connections = self._connections.get(client_id, [])
        if connection is None:
            removed_connections = list(connections)
            self._connections.pop(client_id, None)
        else:
            removed_connections = [item for item in connections if item is connection]
            remaining_connections = [
                item for item in connections if item is not connection
            ]
            if remaining_connections:
                self._connections[client_id] = remaining_connections
            elif removed_connections:
                self._connections.pop(client_id, None)

        for removed in removed_connections:
            self._fail_pending_for_connection(
                client_id,
                removed,
                code="MCP_CONNECTION_LOST",
                message=f"Thin client disconnected: {client_id}",
            )

        return bool(removed_connections) and not self.is_connected(client_id)

    async def disconnect(self, client_id: str, *, code: int = 1000) -> None:
        connections = list(self._connections.get(client_id, []))
        await self.unregister(client_id)
        for connection in connections:
            try:
                await connection.websocket.close(code=code)
            except RuntimeError:
                pass

    def _fail_pending_for_connection(
        self,
        client_id: str,
        connection: ThinClientConnection,
        *,
        code: str,
        message: str,
    ) -> None:
        for request_id, pending in list(self._pending.items()):
            if pending.client_id != client_id or pending.connection is not connection:
                continue
            if not pending.future.done():
                pending.future.set_exception(
                    ThinClientMcpError(
                        code,
                        message,
                        unknown_outcome=pending.unknown_if_interrupted,
                        retryable=not pending.unknown_if_interrupted,
                        http_status=409,
                    )
                )
            self._pending.pop(request_id, None)

    async def complete(self, request_id: str, message: dict[str, Any]) -> None:
        pending = self._pending.pop(request_id, None)
        future = pending.future if pending else None
        if future and not future.done():
            future.set_result(message)

    async def complete_mcp(
        self,
        client_id: str,
        connection: ThinClientConnection,
        message: dict[str, Any],
    ) -> bool:
        request_id = str(message.get("request_id", ""))
        pending = self._pending.get(request_id)
        if pending is None or pending.kind != "mcp":
            return False
        exact = (
            pending.client_id == client_id
            and pending.connection is connection
            and not connection.stale
            and str(message.get("connection_instance_id", ""))
            == connection.connection_instance_id
            and str(message.get("runtime_id", "")) == pending.runtime_id
            and str(message.get("local_server_id", "")) == pending.local_server_id
        )
        if not exact:
            return False
        self._pending.pop(request_id, None)
        if not pending.future.done():
            pending.future.set_result(message)
        return True

    async def request(
        self,
        client_id: str,
        *,
        tool: str,
        arguments: dict[str, Any],
        timeout_seconds: int,
    ) -> dict[str, Any]:
        connections = self._connections.get(client_id, [])
        if not connections:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Thin client is not connected",
            )
        connection = connections[-1]
        request_id = str(uuid.uuid4())
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        pending = PendingThinClientRequest(
            client_id=client_id,
            connection=connection,
            future=future,
            kind="legacy",
        )
        self._pending[request_id] = pending
        try:
            async with connection.send_lock:
                await connection.websocket.send_json(
                    {
                        "type": "tool_call",
                        "request_id": request_id,
                        "tool": tool,
                        "arguments": arguments,
                    }
                )
                pending.dispatched = True
            return await asyncio.wait_for(future, timeout=timeout_seconds)
        except asyncio.TimeoutError as exc:
            self._pending.pop(request_id, None)
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Thin client tool timed out",
            ) from exc
        except RuntimeError as exc:
            self._pending.pop(request_id, None)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=str(exc)
            ) from exc

    async def request_mcp(
        self,
        client_id: str,
        *,
        runtime_id: str,
        local_server_id: str,
        connection_instance_id: str,
        request_id: str,
        server_id: str,
        revision_id: str,
        tool_name: str,
        schema_hash: str,
        catalog_generation: int,
        arguments: dict[str, Any],
        action_class: str,
        timeout_seconds: float,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        connection = self.active_mcp_connection(
            client_id,
            runtime_id=runtime_id,
            local_server_id=local_server_id,
        )
        if connection.connection_instance_id != connection_instance_id:
            raise ThinClientMcpError(
                "MCP_STALE_CONNECTION",
                "The selected MCP connection instance is stale",
                retryable=True,
                http_status=409,
            )
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        pending = PendingThinClientRequest(
            client_id=client_id,
            connection=connection,
            future=future,
            kind="mcp",
            runtime_id=runtime_id,
            local_server_id=local_server_id,
            action_class=action_class,
        )
        self._pending[request_id] = pending
        payload = {
            "type": "mcp_call",
            "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
            "request_id": request_id,
            "connection_instance_id": connection.connection_instance_id,
            "runtime_id": runtime_id,
            "local_server_id": local_server_id,
            "server_id": server_id,
            "revision_id": revision_id,
            "tool_name": tool_name,
            "schema_hash": schema_hash,
            "catalog_generation": catalog_generation,
            "arguments": arguments,
            "action_class": action_class,
            "idempotency_key": idempotency_key,
        }
        try:
            async with connection.send_lock:
                await connection.websocket.send_json(payload)
                pending.dispatched = True
            return await asyncio.wait_for(
                asyncio.shield(future), timeout=timeout_seconds
            )
        except asyncio.TimeoutError as exc:
            self._pending.pop(request_id, None)
            await self.send_mcp_control(
                client_id,
                runtime_id=runtime_id,
                local_server_id=local_server_id,
                connection_instance_id=connection_instance_id,
                message={
                    "type": "mcp_cancel",
                    "request_id": request_id,
                    "reason": "Gateway deadline exceeded",
                },
                best_effort=True,
            )
            raise ThinClientMcpError(
                "MCP_CALL_TIMEOUT",
                "Local MCP call exceeded the Gateway deadline",
                unknown_outcome=pending.unknown_if_interrupted,
                retryable=False,
                http_status=504,
            ) from exc
        except ThinClientMcpError:
            self._pending.pop(request_id, None)
            raise
        except RuntimeError as exc:
            self._pending.pop(request_id, None)
            raise ThinClientMcpError(
                "MCP_CONNECTION_LOST",
                "Local MCP connection was lost",
                unknown_outcome=pending.unknown_if_interrupted,
                retryable=not pending.unknown_if_interrupted,
                http_status=409,
            ) from exc

    async def send_mcp_control(
        self,
        client_id: str,
        *,
        runtime_id: str,
        local_server_id: str,
        connection_instance_id: str,
        message: dict[str, Any],
        best_effort: bool = False,
    ) -> bool:
        try:
            connection = self.active_mcp_connection(
                client_id,
                runtime_id=runtime_id,
                local_server_id=local_server_id,
            )
            if connection.connection_instance_id != connection_instance_id:
                raise ThinClientMcpError(
                    "MCP_STALE_CONNECTION",
                    "The selected MCP connection instance is stale",
                )
            payload = {
                "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
                "connection_instance_id": connection.connection_instance_id,
                "runtime_id": runtime_id,
                "local_server_id": local_server_id,
                **message,
            }
            async with connection.send_lock:
                await connection.websocket.send_json(payload)
            return True
        except (RuntimeError, ThinClientMcpError):
            if best_effort:
                return False
            raise


thin_client_manager = ThinClientConnectionManager()
