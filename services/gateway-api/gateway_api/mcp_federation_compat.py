from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

MCP_SDK_REQUIREMENT = "mcp>=2.1.1,<3"
MCP_CURRENT_PROTOCOL_VERSION = "2026-07-28"
MCP_STABLE_PROTOCOL_VERSION = "2025-11-25"
PREFERRED_MCP_PROTOCOL_VERSION = MCP_STABLE_PROTOCOL_VERSION
LEGACY_MCP_PROTOCOL_VERSIONS = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    MCP_STABLE_PROTOCOL_VERSION,
)
MODERN_MCP_PROTOCOL_VERSIONS = (MCP_CURRENT_PROTOCOL_VERSION,)
SUPPORTED_MCP_PROTOCOL_VERSIONS = LEGACY_MCP_PROTOCOL_VERSIONS + MODERN_MCP_PROTOCOL_VERSIONS
LEGACY_HTTP_PROTOCOL_FALLBACK_VERSION = "2025-03-26"
MCP_TIMEOUT_STRATEGY = "protocol_cancellation"
USE_MCP_SDK_READ_TIMEOUTS = True
MCP_PRESENTATION_MODES = (
    "catalog_broker",
    "deferred_native",
    "native_projected",
)
MCP_PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
MCP_CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
MCP_CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
MCP_SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"
MCP_APPS_EXTENSION_ID = "io.modelcontextprotocol/ui"
MCP_TASKS_EXTENSION_ID = "io.modelcontextprotocol/tasks"
QUALIFIED_SERVER_EXTENSIONS = frozenset()
MCP_HEADER_MISMATCH_CODE = -32020
MCP_UNSUPPORTED_PROTOCOL_VERSION_CODE = -32022

SERVER_CAPABILITY_NAMES = (
    "tools",
    "resources",
    "prompts",
    "logging",
    "completions",
    "extensions",
    "tasks",
    "experimental",
)
CLIENT_CAPABILITY_NAMES = (
    "roots",
    "sampling",
    "elicitation",
    "extensions",
    "tasks",
    "experimental",
)
FEDERATED_SERVER_CAPABILITIES = frozenset({"tools"})
GATEWAY_UPSTREAM_CLIENT_CAPABILITIES = frozenset()
_PROTOCOL_VERSION = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_BASE64_SENTINEL = re.compile(r"^=\?base64\?([A-Za-z0-9+/]*={0,2})\?=$")
_NAMED_METHOD_FIELDS = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
    "tasks/get": "taskId",
    "tasks/update": "taskId",
    "tasks/cancel": "taskId",
}


class McpProtocolAdmissionError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "MCP_UNSUPPORTED_PROTOCOL_VERSION",
        jsonrpc_code: int = -32602,
        http_status: int = 400,
        data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.jsonrpc_code = jsonrpc_code
        self.http_status = http_status
        self.data = data


@dataclass(frozen=True, slots=True)
class CapabilityAdmission:
    protocol_version: str
    observed_server_capabilities: tuple[str, ...]
    federated_server_capabilities: tuple[str, ...]
    observed_not_federated: tuple[str, ...]
    missing_required_capabilities: tuple[str, ...]
    observed_extensions: tuple[str, ...] = ()
    qualified_extensions: tuple[str, ...] = ()

    @property
    def admitted(self) -> bool:
        return not self.missing_required_capabilities

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "admitted": self.admitted}


@dataclass(frozen=True, slots=True)
class ModernRequestAdmission:
    protocol_version: str
    client_capabilities: dict[str, Any]
    client_info: dict[str, Any] | None
    requested_extensions: tuple[str, ...]


def protocol_era(version: str) -> str:
    if version in MODERN_MCP_PROTOCOL_VERSIONS:
        return "modern"
    if version in LEGACY_MCP_PROTOCOL_VERSIONS:
        return "legacy"
    raise McpProtocolAdmissionError(
        f"Protocol version {version} is not accepted by the compatibility matrix",
        jsonrpc_code=MCP_UNSUPPORTED_PROTOCOL_VERSION_CODE,
        data={"supported": list(SUPPORTED_MCP_PROTOCOL_VERSIONS), "requested": version},
    )


def _validated_protocol_version(
    requested: object,
    *,
    allowed: tuple[str, ...],
    unsupported_jsonrpc_code: int = -32602,
) -> str:
    if not isinstance(requested, str) or not requested:
        raise McpProtocolAdmissionError("Protocol version is required")
    if requested in allowed:
        return requested
    if _PROTOCOL_VERSION.fullmatch(requested):
        raise McpProtocolAdmissionError(
            f"Protocol version {requested} is not accepted by the compatibility matrix",
            jsonrpc_code=unsupported_jsonrpc_code,
            data={"supported": list(allowed), "requested": requested},
        )
    raise McpProtocolAdmissionError("Protocol version must use the YYYY-MM-DD format")


def negotiate_legacy_initialize_protocol_version(requested: object) -> str:
    return _validated_protocol_version(
        requested,
        allowed=LEGACY_MCP_PROTOCOL_VERSIONS,
    )


def negotiate_gateway_protocol_version(requested: object) -> str:
    return negotiate_legacy_initialize_protocol_version(requested)


def validate_http_protocol_version(header_value: str | None) -> str:
    if header_value is None or not header_value.strip():
        return LEGACY_HTTP_PROTOCOL_FALLBACK_VERSION
    return _validated_protocol_version(
        header_value.strip(),
        allowed=SUPPORTED_MCP_PROTOCOL_VERSIONS,
    )


def gateway_public_server_capabilities(*, tools_list_changed: bool) -> dict[str, Any]:
    return {
        "tools": {"listChanged": True} if tools_list_changed else {},
    }


def gateway_public_discover_result(
    *,
    server_name: str,
    server_version: str,
    tools_list_changed: bool,
) -> dict[str, Any]:
    return {
        "supportedVersions": list(SUPPORTED_MCP_PROTOCOL_VERSIONS),
        "capabilities": gateway_public_server_capabilities(
            tools_list_changed=tools_list_changed
        ),
        "ttlMs": 0,
        "cacheScope": "private",
        "resultType": "complete",
        "_meta": {
            MCP_SERVER_INFO_META_KEY: {
                "name": server_name,
                "version": server_version,
            }
        },
    }


def modern_server_info_meta(*, server_name: str, server_version: str) -> dict[str, Any]:
    return {
        MCP_SERVER_INFO_META_KEY: {
            "name": server_name,
            "version": server_version,
        }
    }


def _routing_header_value(value: str | None, label: str) -> str:
    if value is None or not value:
        raise McpProtocolAdmissionError(
            f"Header mismatch: missing required header {label}",
            code="MCP_HEADER_MISMATCH",
            jsonrpc_code=MCP_HEADER_MISMATCH_CODE,
        )
    match = _BASE64_SENTINEL.fullmatch(value)
    if match is None:
        if value.startswith("=?base64?") or value.endswith("?="):
            raise McpProtocolAdmissionError(
                f"Header mismatch: malformed {label} header",
                code="MCP_HEADER_MISMATCH",
                jsonrpc_code=MCP_HEADER_MISMATCH_CODE,
            )
        return value
    try:
        decoded = base64.b64decode(match.group(1), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise McpProtocolAdmissionError(
            f"Header mismatch: malformed {label} header",
            code="MCP_HEADER_MISMATCH",
            jsonrpc_code=MCP_HEADER_MISMATCH_CODE,
        ) from exc
    return decoded


def _validated_client_info(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise McpProtocolAdmissionError("Modern request clientInfo must be an object")
    payload = dict(value)
    if not isinstance(payload.get("name"), str) or not payload["name"]:
        raise McpProtocolAdmissionError("Modern request clientInfo.name is invalid")
    if not isinstance(payload.get("version"), str) or not payload["version"]:
        raise McpProtocolAdmissionError("Modern request clientInfo.version is invalid")
    return payload


def validate_modern_request_envelope(
    body: Mapping[str, Any],
    headers: Mapping[str, str],
) -> ModernRequestAdmission:
    method = body.get("method")
    if not isinstance(method, str) or not method:
        raise McpProtocolAdmissionError("Modern MCP request method is required")
    params = body.get("params")
    if not isinstance(params, Mapping):
        raise McpProtocolAdmissionError("Modern MCP request params must be an object")
    meta = params.get("_meta")
    if not isinstance(meta, Mapping):
        raise McpProtocolAdmissionError("Modern MCP request params._meta is required")
    protocol_version = _validated_protocol_version(
        meta.get(MCP_PROTOCOL_VERSION_META_KEY),
        allowed=MODERN_MCP_PROTOCOL_VERSIONS,
        unsupported_jsonrpc_code=MCP_UNSUPPORTED_PROTOCOL_VERSION_CODE,
    )
    header_protocol = headers.get("mcp-protocol-version")
    if header_protocol is None:
        raise McpProtocolAdmissionError(
            "Header mismatch: missing required header MCP-Protocol-Version",
            code="MCP_HEADER_MISMATCH",
            jsonrpc_code=MCP_HEADER_MISMATCH_CODE,
        )
    if header_protocol != protocol_version:
        raise McpProtocolAdmissionError(
            "Header mismatch: MCP-Protocol-Version does not match request _meta",
            code="MCP_HEADER_MISMATCH",
            jsonrpc_code=MCP_HEADER_MISMATCH_CODE,
        )
    method_header = _routing_header_value(headers.get("mcp-method"), "Mcp-Method")
    if method_header != method:
        raise McpProtocolAdmissionError(
            "Header mismatch: Mcp-Method does not match request method",
            code="MCP_HEADER_MISMATCH",
            jsonrpc_code=MCP_HEADER_MISMATCH_CODE,
        )
    name_field = _NAMED_METHOD_FIELDS.get(method)
    if name_field is not None:
        body_name = params.get(name_field)
        if not isinstance(body_name, str) or not body_name:
            raise McpProtocolAdmissionError(
                f"Modern request params.{name_field} is required"
            )
        name_header = _routing_header_value(headers.get("mcp-name"), "Mcp-Name")
        if name_header != body_name:
            raise McpProtocolAdmissionError(
                "Header mismatch: Mcp-Name does not match request body",
                code="MCP_HEADER_MISMATCH",
                jsonrpc_code=MCP_HEADER_MISMATCH_CODE,
            )
    client_capabilities = meta.get(MCP_CLIENT_CAPABILITIES_META_KEY)
    if not isinstance(client_capabilities, Mapping):
        raise McpProtocolAdmissionError(
            "Modern request clientCapabilities must be an object"
        )
    client_capabilities_payload = dict(client_capabilities)
    extensions = client_capabilities_payload.get("extensions")
    if extensions is None:
        requested_extensions: tuple[str, ...] = ()
    elif isinstance(extensions, Mapping):
        requested_extensions = tuple(sorted(str(key) for key in extensions))
    else:
        raise McpProtocolAdmissionError(
            "Modern request clientCapabilities.extensions must be an object"
        )
    return ModernRequestAdmission(
        protocol_version=protocol_version,
        client_capabilities=client_capabilities_payload,
        client_info=_validated_client_info(meta.get(MCP_CLIENT_INFO_META_KEY)),
        requested_extensions=requested_extensions,
    )


def public_request_protocol_admission(
    body: Mapping[str, Any],
    headers: Mapping[str, str],
) -> str | ModernRequestAdmission:
    params = body.get("params")
    meta = params.get("_meta") if isinstance(params, Mapping) else None
    modern_meta = (
        meta.get(MCP_PROTOCOL_VERSION_META_KEY)
        if isinstance(meta, Mapping)
        else None
    )
    header_value = headers.get("mcp-protocol-version")
    if modern_meta is not None or header_value in MODERN_MCP_PROTOCOL_VERSIONS:
        return validate_modern_request_envelope(body, headers)
    return validate_http_protocol_version(header_value)


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


def _extension_names(capabilities: Any) -> tuple[str, ...]:
    payload = _model_mapping(capabilities)
    extensions = payload.get("extensions")
    if not isinstance(extensions, Mapping):
        return ()
    return tuple(sorted(str(name) for name in extensions))


def admit_upstream_capabilities(
    *,
    protocol_version: str,
    capabilities: Any,
) -> CapabilityAdmission:
    protocol_era(protocol_version)
    observed = classify_server_capabilities(capabilities)
    federated = tuple(sorted(FEDERATED_SERVER_CAPABILITIES.intersection(observed)))
    ignored = tuple(sorted(set(observed).difference(FEDERATED_SERVER_CAPABILITIES)))
    missing = () if "tools" in observed else ("tools",)
    observed_extensions = _extension_names(capabilities)
    qualified_extensions = tuple(
        sorted(QUALIFIED_SERVER_EXTENSIONS.intersection(observed_extensions))
    )
    admission = CapabilityAdmission(
        protocol_version=protocol_version,
        observed_server_capabilities=observed,
        federated_server_capabilities=federated,
        observed_not_federated=ignored,
        missing_required_capabilities=missing,
        observed_extensions=observed_extensions,
        qualified_extensions=qualified_extensions,
    )
    if not admission.admitted:
        raise McpProtocolAdmissionError(
            "Upstream server did not advertise the tools capability",
            code="MCP_REQUIRED_CAPABILITY_MISSING",
        )
    return admission


def admit_upstream_initialize(initialized: Any) -> CapabilityAdmission:
    protocol_version = negotiate_legacy_initialize_protocol_version(
        getattr(initialized, "protocolVersion", None)
    )
    return admit_upstream_capabilities(
        protocol_version=protocol_version,
        capabilities=getattr(initialized, "capabilities", None),
    )


def admit_upstream_discover(
    discovered: Any,
    *,
    protocol_version: str,
) -> CapabilityAdmission:
    if protocol_version not in MODERN_MCP_PROTOCOL_VERSIONS:
        raise McpProtocolAdmissionError(
            f"Discovery negotiated unexpected protocol version {protocol_version}"
        )
    supported = getattr(discovered, "supportedVersions", None)
    if supported is None:
        supported = getattr(discovered, "supported_versions", None)
    if not isinstance(supported, (list, tuple)) or protocol_version not in supported:
        raise McpProtocolAdmissionError(
            "Upstream discovery result does not include the negotiated protocol version"
        )
    return admit_upstream_capabilities(
        protocol_version=protocol_version,
        capabilities=getattr(discovered, "capabilities", None),
    )
