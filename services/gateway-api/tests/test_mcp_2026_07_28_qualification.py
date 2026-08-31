from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from gateway_api.mcp_federation_compat import (
    LEGACY_MCP_PROTOCOL_VERSIONS,
    MCP_APPS_EXTENSION_ID,
    MCP_CLIENT_CAPABILITIES_META_KEY,
    MCP_CLIENT_INFO_META_KEY,
    MCP_CURRENT_PROTOCOL_VERSION,
    MCP_HEADER_MISMATCH_CODE,
    MCP_PROTOCOL_VERSION_META_KEY,
    MCP_SDK_REQUIREMENT,
    MCP_TASKS_EXTENSION_ID,
    MCP_UNSUPPORTED_PROTOCOL_VERSION_CODE,
    MODERN_MCP_PROTOCOL_VERSIONS,
    PREFERRED_MCP_PROTOCOL_VERSION,
    QUALIFIED_SERVER_EXTENSIONS,
    McpProtocolAdmissionError,
    admit_upstream_discover,
    gateway_public_discover_result,
    negotiate_gateway_protocol_version,
    protocol_era,
    validate_modern_request_envelope,
)


def _body(method: str, params: dict[str, object] | None = None) -> dict[str, object]:
    payload = dict(params or {})
    payload["_meta"] = {
        MCP_PROTOCOL_VERSION_META_KEY: MCP_CURRENT_PROTOCOL_VERSION,
        MCP_CLIENT_CAPABILITIES_META_KEY: {"extensions": {}},
        MCP_CLIENT_INFO_META_KEY: {"name": "qualification-client", "version": "1"},
    }
    return {"jsonrpc": "2.0", "id": "modern", "method": method, "params": payload}


def _headers(method: str, *, name: str | None = None) -> dict[str, str]:
    result = {
        "mcp-protocol-version": MCP_CURRENT_PROTOCOL_VERSION,
        "mcp-method": method,
    }
    if name is not None:
        result["mcp-name"] = name
    return result


def test_protocol_eras_are_version_fenced() -> None:
    assert MCP_SDK_REQUIREMENT == "mcp>=2.1.1,<3"
    assert PREFERRED_MCP_PROTOCOL_VERSION == "2025-11-25"
    assert MODERN_MCP_PROTOCOL_VERSIONS == ("2026-07-28",)
    assert protocol_era(MCP_CURRENT_PROTOCOL_VERSION) == "modern"
    for version in LEGACY_MCP_PROTOCOL_VERSIONS:
        assert protocol_era(version) == "legacy"
        assert negotiate_gateway_protocol_version(version) == version
    with pytest.raises(McpProtocolAdmissionError) as exc_info:
        negotiate_gateway_protocol_version(MCP_CURRENT_PROTOCOL_VERSION)
    assert exc_info.value.jsonrpc_code == -32602


def test_modern_request_requires_exact_protocol_and_method_headers() -> None:
    body = _body("server/discover")
    admitted = validate_modern_request_envelope(body, _headers("server/discover"))
    assert admitted.protocol_version == MCP_CURRENT_PROTOCOL_VERSION
    assert admitted.client_info == {"name": "qualification-client", "version": "1"}

    with pytest.raises(McpProtocolAdmissionError) as exc_info:
        validate_modern_request_envelope(
            body,
            {
                "mcp-protocol-version": MCP_CURRENT_PROTOCOL_VERSION,
                "mcp-method": "tools/list",
            },
        )
    assert exc_info.value.jsonrpc_code == MCP_HEADER_MISMATCH_CODE


def test_modern_named_routing_supports_base64_sentinel_and_fails_closed() -> None:
    name = "über tool"
    encoded = base64.b64encode(name.encode("utf-8")).decode("ascii")
    body = _body("tools/call", {"name": name, "arguments": {}})
    admitted = validate_modern_request_envelope(
        body,
        _headers("tools/call", name=f"=?base64?{encoded}?="),
    )
    assert admitted.protocol_version == MCP_CURRENT_PROTOCOL_VERSION

    with pytest.raises(McpProtocolAdmissionError) as exc_info:
        validate_modern_request_envelope(body, _headers("tools/call", name="other"))
    assert exc_info.value.jsonrpc_code == MCP_HEADER_MISMATCH_CODE


def test_modern_unsupported_protocol_uses_dedicated_error_code() -> None:
    body = _body("server/discover")
    body["params"]["_meta"][MCP_PROTOCOL_VERSION_META_KEY] = "2026-08-01"
    with pytest.raises(McpProtocolAdmissionError) as exc_info:
        validate_modern_request_envelope(
            body,
            {
                "mcp-protocol-version": "2026-08-01",
                "mcp-method": "server/discover",
            },
        )
    assert exc_info.value.jsonrpc_code == MCP_UNSUPPORTED_PROTOCOL_VERSION_CODE


def test_apps_and_tasks_are_observed_but_not_qualified() -> None:
    assert QUALIFIED_SERVER_EXTENSIONS == set()
    discovered = SimpleNamespace(
        supportedVersions=[MCP_CURRENT_PROTOCOL_VERSION],
        capabilities={
            "tools": {"listChanged": True},
            "extensions": {
                MCP_APPS_EXTENSION_ID: {"version": "1"},
                MCP_TASKS_EXTENSION_ID: {"version": "1"},
            },
        },
    )
    admission = admit_upstream_discover(
        discovered,
        protocol_version=MCP_CURRENT_PROTOCOL_VERSION,
    )
    assert admission.federated_server_capabilities == ("tools",)
    assert admission.qualified_extensions == ()
    assert admission.observed_extensions == tuple(
        sorted((MCP_APPS_EXTENSION_ID, MCP_TASKS_EXTENSION_ID))
    )


def test_public_discover_advertises_tools_only_and_current_version() -> None:
    result = gateway_public_discover_result(
        server_name="gateway",
        server_version="test",
        tools_list_changed=True,
    )
    assert result["supportedVersions"][-1] == MCP_CURRENT_PROTOCOL_VERSION
    assert result["capabilities"] == {"tools": {"listChanged": True}}
    assert "extensions" not in result["capabilities"]
    assert "tasks" not in result["capabilities"]
    assert result["ttlMs"] == 0
    assert result["cacheScope"] == "private"
    assert result["resultType"] == "complete"
