from __future__ import annotations

import asyncio
import contextlib
import socket
from importlib.metadata import version as distribution_version
from dataclasses import dataclass, field
from typing import Annotated, AsyncIterator, Literal

import uvicorn

from gateway_api.mcp_federation_compat import (
    MCP_SDK_REQUIREMENT,
    MCP_TIMEOUT_STRATEGY,
    PREFERRED_MCP_PROTOCOL_VERSION,
    SUPPORTED_MCP_PROTOCOL_VERSIONS,
    USE_MCP_SDK_READ_TIMEOUTS,
)
from mcp.shared.version import LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS

from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.lowlevel.server import NotificationOptions
from mcp.shared.exceptions import McpError
from pydantic import BaseModel, Field


class StructuredReply(BaseModel):
    mode: Literal["compact", "full"]
    count: int
    nested: dict[str, list[int]]


@dataclass
class ProbeState:
    cancellable_started: asyncio.Event = field(default_factory=asyncio.Event)
    cancellable_cancelled: asyncio.Event = field(default_factory=asyncio.Event)
    dynamic_added: bool = False


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _build_server(*, stateless: bool) -> tuple[FastMCP, ProbeState]:
    state = ProbeState()
    server = FastMCP(
        name="gateway-mcp-sdk-qualification",
        host="127.0.0.1",
        stateless_http=stateless,
        json_response=stateless,
        streamable_http_path="/mcp",
        log_level="WARNING",
    )
    create_options = server._mcp_server.create_initialization_options
    server._mcp_server.create_initialization_options = lambda: create_options(
        NotificationOptions(tools_changed=True)
    )

    @server.tool()
    async def structured_echo(
        mode: Literal["compact", "full"],
        count: Annotated[int, Field(ge=1, le=5)],
    ) -> StructuredReply:
        return StructuredReply(
            mode=mode, count=count, nested={"values": list(range(count))}
        )

    @server.tool()
    async def progressive_probe(
        steps: Annotated[int, Field(ge=1, le=5)],
        ctx: Context,
    ) -> dict[str, int]:
        for current in range(1, steps + 1):
            await ctx.report_progress(current, steps, f"step {current}")
            await asyncio.sleep(0.01)
        return {"steps": steps}

    @server.tool()
    async def cancellable_probe(delay_seconds: float, ctx: Context) -> str:
        del ctx
        state.cancellable_started.set()
        try:
            await asyncio.sleep(delay_seconds)
        except asyncio.CancelledError:
            state.cancellable_cancelled.set()
            raise
        return "completed"

    async def dynamic_probe(value: str) -> str:
        return f"dynamic:{value}"

    @server.tool()
    async def publish_dynamic_tool(ctx: Context) -> dict[str, bool]:
        if not state.dynamic_added:
            server.add_tool(dynamic_probe, name="dynamic_probe")
            state.dynamic_added = True
        await ctx.request_context.session.send_tool_list_changed()
        return {"added": state.dynamic_added}

    return server, state


@contextlib.asynccontextmanager
async def _running_server(
    *, stateless: bool
) -> AsyncIterator[tuple[FastMCP, ProbeState, str]]:
    server, state = _build_server(stateless=stateless)
    port = _free_port()
    uvicorn_server = uvicorn.Server(
        uvicorn.Config(
            server.streamable_http_app(),
            host="127.0.0.1",
            port=port,
            log_level="critical",
            lifespan="on",
            timeout_graceful_shutdown=1,
        )
    )
    task = asyncio.create_task(uvicorn_server.serve())
    try:
        for _ in range(300):
            if uvicorn_server.started:
                break
            if task.done():
                await task
            await asyncio.sleep(0.01)
        else:
            raise RuntimeError("qualification server did not start")
        yield server, state, f"http://127.0.0.1:{port}/mcp"
    finally:
        uvicorn_server.should_exit = True
        await asyncio.wait_for(task, timeout=5)


async def _initialize_version(
    session: ClientSession, version: str
) -> types.InitializeResult:
    result = await session.send_request(
        types.ClientRequest(
            types.InitializeRequest(
                params=types.InitializeRequestParams(
                    protocolVersion=version,
                    capabilities=types.ClientCapabilities(),
                    clientInfo=types.Implementation(
                        name="gateway-qualification", version="1"
                    ),
                )
            )
        ),
        types.InitializeResult,
    )
    await session.send_notification(
        types.ClientNotification(types.InitializedNotification())
    )
    return result


async def qualify_protocol_versions() -> None:
    async with _running_server(stateless=True) as (_, _, url):
        for version in ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]:
            async with streamable_http_client(url, terminate_on_close=False) as (
                read_stream,
                write_stream,
                _,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    initialized = await _initialize_version(session, version)
                    assert initialized.protocolVersion == version


async def qualify_stateful_transport() -> None:
    notifications: list[str] = []
    list_changed = asyncio.Event()

    async def handler(message) -> None:
        if isinstance(message, types.ServerNotification):
            notifications.append(message.root.method)
            if isinstance(message.root, types.ToolListChangedNotification):
                list_changed.set()

    async with _running_server(stateless=False) as (server, state, url):
        async with streamable_http_client(url, terminate_on_close=True) as (
            read_stream,
            write_stream,
            get_session_id,
        ):
            async with ClientSession(
                read_stream, write_stream, message_handler=handler
            ) as session:
                initialized = await session.initialize()
                assert initialized.protocolVersion == "2025-11-25"
                assert initialized.capabilities.tools is not None
                assert initialized.capabilities.tools.listChanged is True
                assert get_session_id()

                listed = await session.list_tools()
                structured = next(
                    tool for tool in listed.tools if tool.name == "structured_echo"
                )
                assert structured.inputSchema["properties"]["mode"]["enum"] == [
                    "compact",
                    "full",
                ]
                assert structured.inputSchema["properties"]["count"]["minimum"] == 1
                assert structured.inputSchema["properties"]["count"]["maximum"] == 5
                assert structured.outputSchema is not None

                called = await session.call_tool(
                    "structured_echo", {"mode": "compact", "count": 3}
                )
                assert called.isError is False
                assert called.structuredContent == {
                    "mode": "compact",
                    "count": 3,
                    "nested": {"values": [0, 1, 2]},
                }

                progress: list[tuple[float, float | None, str | None]] = []

                async def progress_callback(
                    value: float, total: float | None, message: str | None
                ) -> None:
                    progress.append((value, total, message))

                progressed = await session.call_tool(
                    "progressive_probe",
                    {"steps": 3},
                    progress_callback=progress_callback,
                )
                assert progressed.structuredContent == {"steps": 3}
                assert progress == [
                    (1.0, 3.0, "step 1"),
                    (2.0, 3.0, "step 2"),
                    (3.0, 3.0, "step 3"),
                ]

                await session.call_tool("publish_dynamic_tool", {})
                await asyncio.wait_for(list_changed.wait(), timeout=2)
                assert "notifications/tools/list_changed" in notifications
                refreshed = await session.list_tools()
                assert any(tool.name == "dynamic_probe" for tool in refreshed.tools)

                request_id = session._request_id
                cancellation = asyncio.create_task(
                    session.call_tool("cancellable_probe", {"delay_seconds": 5.0})
                )
                await asyncio.wait_for(state.cancellable_started.wait(), timeout=2)
                await session.send_notification(
                    types.ClientNotification(
                        types.CancelledNotification(
                            params=types.CancelledNotificationParams(
                                requestId=request_id,
                                reason="qualification cancellation",
                            )
                        )
                    )
                )
                try:
                    await cancellation
                except McpError as exc:
                    assert exc.error.code == 0
                    assert exc.error.message == "Request cancelled"
                else:
                    raise AssertionError("cancelled call unexpectedly completed")
                await asyncio.wait_for(state.cancellable_cancelled.wait(), timeout=2)

                after_cancel = await session.call_tool(
                    "structured_echo", {"mode": "full", "count": 1}
                )
                assert after_cancel.isError is False

        async with streamable_http_client(url, terminate_on_close=True) as (
            recovery_read_stream,
            recovery_write_stream,
            recovery_session_id,
        ):
            async with ClientSession(
                recovery_read_stream, recovery_write_stream
            ) as recovery_session:
                await recovery_session.initialize()
                assert recovery_session_id()
                after_reconnect = await recovery_session.call_tool(
                    "structured_echo", {"mode": "full", "count": 1}
                )
                assert after_reconnect.isError is False

        assert server._session_manager is not None
        assert server._session_manager._server_instances
    assert server._session_manager is not None
    assert not server._session_manager._server_instances


async def qualify_stateless_transport() -> None:
    async with _running_server(stateless=True) as (_, _, url):
        async with streamable_http_client(url) as (
            read_stream,
            write_stream,
            get_session_id,
        ):
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                assert initialized.protocolVersion == "2025-11-25"
                assert get_session_id() is None
                first = await session.list_tools()
                second = await session.call_tool(
                    "structured_echo", {"mode": "compact", "count": 2}
                )
                assert any(tool.name == "structured_echo" for tool in first.tools)
                assert second.structuredContent["count"] == 2


def test_sdk_policy_matches_official_sdk() -> None:
    sdk_version = tuple(
        int(part) for part in distribution_version("mcp").split(".")[:3]
    )
    assert sdk_version >= (1, 28, 1)
    assert sdk_version[0] < 2
    assert MCP_SDK_REQUIREMENT == "mcp>=1.28.1,<2"
    assert PREFERRED_MCP_PROTOCOL_VERSION == LATEST_PROTOCOL_VERSION
    assert set(SUPPORTED_MCP_PROTOCOL_VERSIONS).issubset(SUPPORTED_PROTOCOL_VERSIONS)
    assert MCP_TIMEOUT_STRATEGY == "protocol_cancellation"
    assert USE_MCP_SDK_READ_TIMEOUTS is False


def test_protocol_negotiation_matrix() -> None:
    asyncio.run(qualify_protocol_versions())


def test_stateful_streamable_http_features() -> None:
    asyncio.run(qualify_stateful_transport())


def test_stateless_streamable_http_features() -> None:
    asyncio.run(qualify_stateless_transport())
