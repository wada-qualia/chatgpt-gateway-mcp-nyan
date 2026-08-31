from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from importlib.metadata import version as distribution_version
from typing import Annotated, Literal

import pytest
import uvicorn
from gateway_api.mcp_federation_compat import (
    MCP_CURRENT_PROTOCOL_VERSION,
    MCP_SDK_REQUIREMENT,
    MCP_TIMEOUT_STRATEGY,
    PREFERRED_MCP_PROTOCOL_VERSION,
    SUPPORTED_MCP_PROTOCOL_VERSIONS,
    USE_MCP_SDK_READ_TIMEOUTS,
)
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from mcp.server import MCPServer
from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.mcpserver.context import Context
from mcp.shared.exceptions import MCPError
from mcp_types import REQUEST_TIMEOUT
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


def _build_server(*, stateless: bool) -> tuple[MCPServer, ProbeState]:
    state = ProbeState()
    server = MCPServer(
        name="gateway-mcp-sdk-qualification",
        log_level="WARNING",
    )
    # MCPServer v2 keeps legacy list-change advertisement at the low-level
    # notification-options seam; opt in explicitly for this compatibility probe.
    lowlevel = server._lowlevel_server
    create_options = lowlevel.create_initialization_options
    lowlevel.create_initialization_options = lambda: create_options(
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
) -> AsyncIterator[tuple[MCPServer, ProbeState, str]]:
    server, state = _build_server(stateless=stateless)
    port = _free_port()
    uvicorn_server = uvicorn.Server(
        uvicorn.Config(
            server.streamable_http_app(
                streamable_http_path="/mcp",
                stateless_http=stateless,
                json_response=stateless,
                host="127.0.0.1",
            ),
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
        types.InitializeRequest(
            params=types.InitializeRequestParams(
                protocol_version=version,
                capabilities=types.ClientCapabilities(),
                client_info=types.Implementation(
                    name="gateway-qualification", version="1"
                ),
            )
        ),
        types.InitializeResult,
    )
    await session.send_notification(types.InitializedNotification())
    return result


async def qualify_protocol_versions() -> None:
    async with _running_server(stateless=True) as (_, _, url):
        for version in ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]:
            async with streamable_http_client(url, terminate_on_close=True) as (  # noqa: SIM117
                read_stream,
                write_stream,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    initialized = await _initialize_version(session, version)
                    assert initialized.protocol_version == version


async def qualify_stateful_transport() -> None:
    notifications: list[str] = []
    list_changed = asyncio.Event()

    async def handler(message) -> None:
        method = getattr(message, "method", None)
        if isinstance(method, str):
            notifications.append(method)
        if isinstance(message, types.ToolListChangedNotification):
            list_changed.set()

    async with _running_server(stateless=False) as (server, state, url):
        async with streamable_http_client(url, terminate_on_close=True) as (
            read_stream,
            write_stream,
        ), ClientSession(
            read_stream, write_stream, message_handler=handler
        ) as session:
            initialized = await session.initialize()
            assert initialized.protocol_version == "2025-11-25"
            assert initialized.capabilities.tools is not None
            assert initialized.capabilities.tools.list_changed is True

            listed = await session.list_tools()
            structured = next(
                tool for tool in listed.tools if tool.name == "structured_echo"
            )
            assert structured.input_schema["properties"]["mode"]["enum"] == [
                "compact",
                "full",
            ]
            assert structured.input_schema["properties"]["count"]["minimum"] == 1
            assert structured.input_schema["properties"]["count"]["maximum"] == 5
            assert structured.output_schema is not None

            called = await session.call_tool(
                "structured_echo", {"mode": "compact", "count": 3}
            )
            assert called.is_error is False
            assert called.structured_content == {
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
            assert progressed.structured_content == {"steps": 3}
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

            with pytest.raises(MCPError) as cancellation:
                await session.call_tool(
                    "cancellable_probe",
                    {"delay_seconds": 5.0},
                    read_timeout_seconds=0.05,
                )
            assert cancellation.value.code == REQUEST_TIMEOUT
            await asyncio.wait_for(state.cancellable_cancelled.wait(), timeout=2)

            after_cancel = await session.call_tool(
                "structured_echo", {"mode": "full", "count": 1}
            )
            assert after_cancel.is_error is False

        async with streamable_http_client(url, terminate_on_close=True) as (
            recovery_read_stream,
            recovery_write_stream,
        ), ClientSession(
            recovery_read_stream, recovery_write_stream
        ) as recovery_session:
            await recovery_session.initialize()
            after_reconnect = await recovery_session.call_tool(
                "structured_echo", {"mode": "full", "count": 1}
            )
            assert after_reconnect.is_error is False

        assert server.session_manager is not None
        assert server.session_manager._server_instances
    assert server.session_manager is not None
    assert not server.session_manager._server_instances


async def qualify_stateless_transport() -> None:
    async with _running_server(stateless=True) as (_, _, url):  # noqa: SIM117
        async with streamable_http_client(url) as (
            read_stream,
            write_stream,
        ):
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                assert initialized.protocol_version == "2025-11-25"
                first = await session.list_tools()
                second = await session.call_tool(
                    "structured_echo", {"mode": "compact", "count": 2}
                )
                assert any(tool.name == "structured_echo" for tool in first.tools)
                assert second.structured_content["count"] == 2


def test_sdk_policy_matches_official_sdk() -> None:
    sdk_version = tuple(
        int(part) for part in distribution_version("mcp").split(".")[:3]
    )
    assert sdk_version >= (2, 1, 1)
    assert sdk_version[0] < 3
    assert MCP_SDK_REQUIREMENT == "mcp>=2.1.1,<3"
    assert MCP_CURRENT_PROTOCOL_VERSION == types.LATEST_PROTOCOL_VERSION
    assert PREFERRED_MCP_PROTOCOL_VERSION == "2025-11-25"
    assert PREFERRED_MCP_PROTOCOL_VERSION in SUPPORTED_MCP_PROTOCOL_VERSIONS
    assert MCP_CURRENT_PROTOCOL_VERSION in SUPPORTED_MCP_PROTOCOL_VERSIONS
    assert MCP_TIMEOUT_STRATEGY == "protocol_cancellation"
    assert USE_MCP_SDK_READ_TIMEOUTS is True


def test_protocol_negotiation_matrix() -> None:
    asyncio.run(qualify_protocol_versions())


def test_stateful_streamable_http_features() -> None:
    asyncio.run(qualify_stateful_transport())


def test_stateless_streamable_http_features() -> None:
    asyncio.run(qualify_stateless_transport())
