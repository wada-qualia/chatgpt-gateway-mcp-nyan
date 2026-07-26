from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Mapping

MCP_SDK_REQUIREMENT = "mcp>=1.28.1,<2"
MCP_STABLE_PROTOCOL_VERSION = "2025-11-25"
PREFERRED_MCP_PROTOCOL_VERSION = MCP_STABLE_PROTOCOL_VERSION
SUPPORTED_MCP_PROTOCOL_VERSIONS = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    MCP_STABLE_PROTOCOL_VERSION,
)
LEGACY_HTTP_PROTOCOL_FALLBACK_VERSION = "2025-03-26"
MCP_TIMEOUT_STRATEGY = "protocol_cancellation"
USE_MCP_SDK_READ_TIMEOUTS = False
MCP_PRESENTATION_MODES = (
    "catalog_broker",
    "deferred_native",
    "native_projected",
)

SERVER_CAPABILITY_NAMES = (
    "tools",
    "resources",
    "prompts",
    "logging",
    "completions",
    "tasks",
    "experimental",
)
CLIENT_CAPABILITY_NAMES = (
    "roots",
    "sampling",
    "elicitation",
    "tasks",
    "experimental",
)
FEDERATED_SERVER_CAPABILITIES = frozenset({"tools"})
GATEWAY_UPSTREAM_CLIENT_CAPABILITIES = frozenset()
_PROTOCOL_VERSION = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class McpProtocolAdmissionError(ValueError):
    def __init__(self, message: str, *, code: str = "MCP_UNSUPPORTED_PROTOCOL_VERSION") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class CapabilityAdmission:
    protocol_version: str
    observed_server_capabilities: tuple[str, ...]
    federated_server_capabilities: tuple[str, ...]
    observed_not_federated: tuple[str, ...]
    missing_required_capabilities: tuple[str, ...]

    @property
    def admitted(self) -> bool:
        return not self.missing_required_capabilities

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "admitted": self.admitted}


def negotiate_gateway_protocol_version(requested: object) -> str:
    if not isinstance(requested, str) or not requested:
        raise McpProtocolAdmissionError("initialize.params.protocolVersion is required")
    if requested in SUPPORTED_MCP_PROTOCOL_VERSIONS:
        return requested
    if _PROTOCOL_VERSION.fullmatch(requested):
        raise McpProtocolAdmissionError(
            f"Protocol version {requested} is not accepted by the production compatibility matrix"
        )
    raise McpProtocolAdmissionError("Protocol version must use the YYYY-MM-DD format")


def validate_http_protocol_version(header_value: str | None) -> str:
    if header_value is None or not header_value.strip():
        return LEGACY_HTTP_PROTOCOL_FALLBACK_VERSION
    return negotiate_gateway_protocol_version(header_value.strip())


def gateway_public_server_capabilities(*, tools_list_changed: bool) -> dict[str, Any]:
    return {
        "tools": {"listChanged": True} if tools_list_changed else {},
    }


def _model_mapping(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        return dict(dumped) if isinstance(dumped, Mapping) else {}
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def classify_server_capabilities(capabilities: Any) -> tuple[str, ...]:
    payload = _model_mapping(capabilities)
    return tuple(sorted(name for name in SERVER_CAPABILITY_NAMES if name in payload))


def admit_upstream_initialize(initialized: Any) -> CapabilityAdmission:
    protocol_version = negotiate_gateway_protocol_version(
        getattr(initialized, "protocolVersion", None)
    )
    observed = classify_server_capabilities(getattr(initialized, "capabilities", None))
    federated = tuple(sorted(FEDERATED_SERVER_CAPABILITIES.intersection(observed)))
    ignored = tuple(sorted(set(observed).difference(FEDERATED_SERVER_CAPABILITIES)))
    missing = () if "tools" in observed else ("tools",)
    admission = CapabilityAdmission(
        protocol_version=protocol_version,
        observed_server_capabilities=observed,
        federated_server_capabilities=federated,
        observed_not_federated=ignored,
        missing_required_capabilities=missing,
    )
    if not admission.admitted:
        raise McpProtocolAdmissionError(
            "Upstream server did not advertise the tools capability",
            code="MCP_REQUIRED_CAPABILITY_MISSING",
        )
    return admission
