from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from mcp import types
import pytest
import yaml

from gateway_api.mcp_federation_compat import (
    CLIENT_CAPABILITY_NAMES,
    FEDERATED_SERVER_CAPABILITIES,
    GATEWAY_UPSTREAM_CLIENT_CAPABILITIES,
    LEGACY_HTTP_PROTOCOL_FALLBACK_VERSION,
    MCP_PRESENTATION_MODES,
    MCP_SDK_REQUIREMENT,
    MCP_STABLE_PROTOCOL_VERSION,
    McpProtocolAdmissionError,
    PREFERRED_MCP_PROTOCOL_VERSION,
    SUPPORTED_MCP_PROTOCOL_VERSIONS,
    admit_upstream_initialize,
    gateway_public_server_capabilities,
    negotiate_gateway_protocol_version,
    validate_http_protocol_version,
)

ROOT = Path(__file__).resolve().parents[3]
MATRIX = ROOT / "configs/mcp-federation/phase-8-protocol-capabilities.yaml"


def test_phase_eight_matrix_matches_runtime_policy() -> None:
    matrix = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
    specification = matrix["specification"]
    assert matrix["task"] == "CMG-FED-810"
    assert specification["stable_protocol_version"] == MCP_STABLE_PROTOCOL_VERSION
    assert tuple(specification["accepted_protocol_versions"]) == (
        SUPPORTED_MCP_PROTOCOL_VERSIONS
    )
    assert specification["legacy_http_header_fallback"] == (
        LEGACY_HTTP_PROTOCOL_FALLBACK_VERSION
    )
    assert matrix["sdk"]["requirement"] == MCP_SDK_REQUIREMENT
    assert tuple(matrix["presentation_modes"]) == MCP_PRESENTATION_MODES
    assert FEDERATED_SERVER_CAPABILITIES == {"tools"}
    advertised_client = matrix["client_capabilities_advertised_to_upstreams"]
    assert set(advertised_client) == set(CLIENT_CAPABILITY_NAMES)
    assert not any(advertised_client.values())
    assert GATEWAY_UPSTREAM_CLIENT_CAPABILITIES == set()
    assert gateway_public_server_capabilities(tools_list_changed=True) == {
        "tools": {"listChanged": True}
    }
    for name, capability in matrix["server_capabilities"].items():
        assert capability["advertised_by_gateway"] is (name == "tools")
        assert capability["federated_end_to_end"] is (name == "tools")


def test_protocol_admission_rejects_drafts_and_malformed_versions() -> None:
    assert PREFERRED_MCP_PROTOCOL_VERSION == "2025-11-25"
    for version in SUPPORTED_MCP_PROTOCOL_VERSIONS:
        assert negotiate_gateway_protocol_version(version) == version
    assert validate_http_protocol_version(None) == "2025-03-26"
    for value in ("2026-01-01", "draft", "2025-11-25-RC", ""):
        with pytest.raises(McpProtocolAdmissionError):
            negotiate_gateway_protocol_version(value)


def test_upstream_capability_admission_is_tools_only() -> None:
    capabilities = types.ServerCapabilities.model_validate(
        {
            "tools": {"listChanged": True},
            "resources": {"subscribe": True, "listChanged": True},
            "prompts": {"listChanged": True},
            "logging": {},
            "tasks": {"list": {}, "cancel": {}, "requests": {}},
            "experimental": {"vendor": {"enabled": True}},
        }
    )
    initialized = SimpleNamespace(
        protocolVersion="2025-11-25",
        capabilities=capabilities,
    )
    admission = admit_upstream_initialize(initialized)
    assert admission.admitted is True
    assert admission.federated_server_capabilities == ("tools",)
    assert set(admission.observed_not_federated) == {
        "experimental",
        "logging",
        "prompts",
        "resources",
        "tasks",
    }

    missing_tools = SimpleNamespace(
        protocolVersion="2025-11-25",
        capabilities=types.ServerCapabilities.model_validate(
            {"resources": {"subscribe": False, "listChanged": False}}
        ),
    )
    with pytest.raises(McpProtocolAdmissionError) as exc_info:
        admit_upstream_initialize(missing_tools)
    assert exc_info.value.code == "MCP_REQUIRED_CAPABILITY_MISSING"
