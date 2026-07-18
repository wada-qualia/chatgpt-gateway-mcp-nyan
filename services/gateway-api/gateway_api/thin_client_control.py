from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, WebSocket, status


@dataclass
class ThinClientConnection:
    websocket: WebSocket
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class ThinClientConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, list[ThinClientConnection]] = {}
        self._pending: dict[str, tuple[str, ThinClientConnection, asyncio.Future[dict[str, Any]]]] = {}

    async def register(self, client_id: str, websocket: WebSocket) -> ThinClientConnection:
        connection = ThinClientConnection(websocket=websocket)
        self._connections.setdefault(client_id, []).append(connection)
        return connection

    def is_connected(self, client_id: str) -> bool:
        return bool(self._connections.get(client_id))

    async def unregister(self, client_id: str, connection: ThinClientConnection | None = None) -> bool:
        connections = self._connections.get(client_id, [])
        if connection is None:
            removed_connections = list(connections)
            self._connections.pop(client_id, None)
        else:
            removed_connections = [item for item in connections if item is connection]
            remaining_connections = [item for item in connections if item is not connection]
            if remaining_connections:
                self._connections[client_id] = remaining_connections
            elif removed_connections:
                self._connections.pop(client_id, None)

        for request_id, (pending_client_id, pending_connection, future) in list(self._pending.items()):
            if pending_client_id == client_id and any(pending_connection is item for item in removed_connections):
                if not future.done():
                    future.set_exception(RuntimeError(f"Thin client disconnected: {client_id}"))
                self._pending.pop(request_id, None)

        return bool(removed_connections) and client_id not in self._connections

    async def disconnect(self, client_id: str, *, code: int = 1000) -> None:
        connections = list(self._connections.get(client_id, []))
        await self.unregister(client_id)
        for connection in connections:
            try:
                await connection.websocket.close(code=code)
            except RuntimeError:
                pass

    async def complete(self, request_id: str, message: dict[str, Any]) -> None:
        pending = self._pending.pop(request_id, None)
        future = pending[2] if pending else None
        if future and not future.done():
            future.set_result(message)

    async def request(self, client_id: str, *, tool: str, arguments: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
        connections = self._connections.get(client_id, [])
        if not connections:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Thin client is not connected")
        connection = connections[-1]
        request_id = str(uuid.uuid4())
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending[request_id] = (client_id, connection, future)
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
            return await asyncio.wait_for(future, timeout=timeout_seconds)
        except asyncio.TimeoutError as exc:
            self._pending.pop(request_id, None)
            raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail="Thin client tool timed out") from exc
        except RuntimeError as exc:
            self._pending.pop(request_id, None)
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


thin_client_manager = ThinClientConnectionManager()
