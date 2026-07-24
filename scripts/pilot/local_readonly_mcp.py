#!/usr/bin/env python3
"""Deterministic non-production stdio MCP used by the Phase 7 pilot."""

from __future__ import annotations

from datetime import UTC, datetime

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP(
    "gateway-phase7-local-pilot",
    instructions="Read-only deterministic MCP fixture for controlled federation qualification.",
)
READ_ONLY = ToolAnnotations(
    title="Phase 7 read-only pilot",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


@mcp.tool(annotations=READ_ONLY, structured_output=True)
def pilot_ping() -> dict[str, str]:
    """Return a deterministic liveness response."""
    return {"status": "ok", "fixture": "phase7-local-readonly-v1"}


@mcp.tool(annotations=READ_ONLY, structured_output=True)
def pilot_echo(message: str) -> dict[str, str | int]:
    """Echo a bounded non-secret message for exact-schema invocation testing."""
    normalized = " ".join(message.split())[:256]
    return {"message": normalized, "length": len(normalized)}


@mcp.tool(annotations=READ_ONLY, structured_output=True)
def pilot_clock() -> dict[str, str]:
    """Return the current UTC timestamp without reading host configuration."""
    return {"utc": datetime.now(UTC).isoformat()}


if __name__ == "__main__":
    mcp.run(transport="stdio")
