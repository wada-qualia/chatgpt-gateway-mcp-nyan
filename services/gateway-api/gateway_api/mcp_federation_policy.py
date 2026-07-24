from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping


class McpOrigin(StrEnum):
    GATEWAY = "gateway"
    THIN_CLIENT = "thin_client"


class McpTransport(StrEnum):
    STREAMABLE_HTTP = "streamable_http"
    LEGACY_SSE = "legacy_sse"
    STDIO = "stdio"
    PRIVATE_HTTP = "private_http"


class McpTrustLevel(StrEnum):
    UNREVIEWED = "unreviewed"
    RESTRICTED = "restricted"
    APPROVED = "approved"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"


class McpActionClass(StrEnum):
    UNKNOWN = "unknown"
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    PRODUCTION = "production"


class McpReadOnlyStatus(StrEnum):
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    REJECTED = "rejected"


class McpExposureMode(StrEnum):
    HIDDEN = "hidden"
    CATALOG_ONLY = "catalog_only"
    NATIVE_PROJECTED = "native_projected"


class McpApprovalClass(StrEnum):
    NONE = "none"
    OPERATOR = "operator"
    QUORUM = "quorum"
    PRODUCTION = "production"


class McpPolicyViolation(ValueError):
    pass


_SECRET_KEY_PATTERN = re.compile(
    r"(?:^|[_\-.])(password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"client[_-]?secret|credential|authorization|cookie)(?:$|[_\-.])",
    re.IGNORECASE,
)
_TOOL_NAME_WRITE_PATTERN = re.compile(
    r"(?:^|[_\-.])(create|update|edit|write|send|post|publish|upload|"
    r"delete|remove|destroy|replay|trigger|restart|deploy|promote|rollback|"
    r"approve|execute|run)(?:$|[_\-.])",
    re.IGNORECASE,
)
_TOOL_NAME_PRODUCTION_PATTERN = re.compile(
    r"(?:^|[_\-.])(production|prod|deploy|promote|rollback)(?:$|[_\-.])",
    re.IGNORECASE,
)
_TOOL_NAME_DESTRUCTIVE_PATTERN = re.compile(
    r"(?:^|[_\-.])(delete|remove|destroy|purge|drop|terminate)(?:$|[_\-.])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class McpAuthorizationDecision:
    allowed: bool
    reason: str
    approval_class: McpApprovalClass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def normalize_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not slug:
        raise McpPolicyViolation("MCP server name does not produce a valid slug")
    return slug[:120]


def find_secret_paths(value: Any, *, path: str = "$") -> list[str]:
    matches: list[str] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            key_text = str(key)
            nested_path = f"{path}.{key_text}"
            if _SECRET_KEY_PATTERN.search(key_text):
                matches.append(nested_path)
            matches.extend(find_secret_paths(nested, path=nested_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            matches.extend(find_secret_paths(nested, path=f"{path}[{index}]"))
    return matches


def reject_secret_shaped_payload(value: Any) -> None:
    matches = find_secret_paths(value)
    if matches:
        raise McpPolicyViolation(
            "Secret-shaped fields are forbidden in federation payloads: "
            + ", ".join(matches[:8])
        )


def validate_credential_binding(
    *,
    origin: McpOrigin,
    binding_type: str | None,
    secret_blob_id: str | None,
) -> None:
    if origin is McpOrigin.THIN_CLIENT:
        if binding_type not in {None, "thin_client_local"}:
            raise McpPolicyViolation(
                "Thin-client MCP servers may use only thin_client_local credentials"
            )
        if secret_blob_id is not None:
            raise McpPolicyViolation(
                "Thin-client-local credentials must not be stored in Gateway secret blobs"
            )
        return
    if binding_type == "thin_client_local":
        raise McpPolicyViolation(
            "Gateway-origin MCP servers cannot use thin_client_local credentials"
        )
    if binding_type in {"oauth", "service_account"} and not secret_blob_id:
        raise McpPolicyViolation(
            "Gateway OAuth and service-account bindings require a backend secret reference"
        )


def derive_risk_evidence(
    *,
    tool_name: str,
    input_schema: Mapping[str, Any],
    upstream_annotations: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    reject_secret_shaped_payload(input_schema)
    annotations = dict(upstream_annotations or {})
    if _TOOL_NAME_PRODUCTION_PATTERN.search(tool_name):
        heuristic = McpActionClass.PRODUCTION
    elif _TOOL_NAME_DESTRUCTIVE_PATTERN.search(tool_name):
        heuristic = McpActionClass.DESTRUCTIVE
    elif _TOOL_NAME_WRITE_PATTERN.search(tool_name):
        heuristic = McpActionClass.WRITE
    else:
        heuristic = McpActionClass.UNKNOWN
    return {
        "heuristic_action_class": heuristic.value,
        "upstream_read_only_hint": annotations.get("readOnlyHint"),
        "upstream_destructive_hint": annotations.get("destructiveHint"),
        "authoritative": False,
    }


def validate_operator_classification(
    *,
    action_class: McpActionClass,
    read_only_status: McpReadOnlyStatus,
) -> None:
    if (
        action_class is McpActionClass.READ
        and read_only_status is not McpReadOnlyStatus.VERIFIED
    ):
        raise McpPolicyViolation(
            "Read action classification requires independently verified read-only status"
        )
    if (
        action_class is not McpActionClass.READ
        and read_only_status is McpReadOnlyStatus.VERIFIED
    ):
        raise McpPolicyViolation(
            "Verified read-only status is valid only for read action classification"
        )


def required_approval_for(action_class: McpActionClass) -> McpApprovalClass:
    return {
        McpActionClass.UNKNOWN: McpApprovalClass.QUORUM,
        McpActionClass.READ: McpApprovalClass.NONE,
        McpActionClass.WRITE: McpApprovalClass.OPERATOR,
        McpActionClass.DESTRUCTIVE: McpApprovalClass.QUORUM,
        McpActionClass.PRODUCTION: McpApprovalClass.PRODUCTION,
    }[action_class]


def authorize_tool_revision(
    *,
    actor_roles: Iterable[str],
    actor_scopes: Iterable[str],
    trust_level: McpTrustLevel,
    exposure_mode: McpExposureMode,
    exposure_enabled: bool,
    action_class: McpActionClass,
    read_only_status: McpReadOnlyStatus,
    required_role: str | None,
    required_scope: str | None,
    allowed_action_classes: Iterable[str],
    approval_class: McpApprovalClass | None = None,
) -> McpAuthorizationDecision:
    roles = set(actor_roles)
    scopes = set(actor_scopes)
    allowed = set(allowed_action_classes)
    if not exposure_enabled or exposure_mode is McpExposureMode.HIDDEN:
        return McpAuthorizationDecision(
            False, "tool exposure is disabled", McpApprovalClass.NONE
        )
    if trust_level in {
        McpTrustLevel.UNREVIEWED,
        McpTrustLevel.QUARANTINED,
        McpTrustLevel.REVOKED,
    }:
        return McpAuthorizationDecision(
            False, f"server trust level is {trust_level.value}", McpApprovalClass.NONE
        )
    if action_class is McpActionClass.UNKNOWN:
        return McpAuthorizationDecision(
            False, "tool risk classification is unknown", McpApprovalClass.NONE
        )
    if action_class.value not in allowed:
        return McpAuthorizationDecision(
            False, "action class is denied by federation policy", McpApprovalClass.NONE
        )
    if required_role and required_role not in roles:
        return McpAuthorizationDecision(
            False, "required role is missing", McpApprovalClass.NONE
        )
    if required_scope and required_scope not in scopes:
        return McpAuthorizationDecision(
            False, "required scope is missing", McpApprovalClass.NONE
        )
    if (
        action_class is McpActionClass.READ
        and read_only_status is not McpReadOnlyStatus.VERIFIED
    ):
        return McpAuthorizationDecision(
            False,
            "read-only status is not independently verified",
            McpApprovalClass.NONE,
        )
    selected_approval = approval_class or required_approval_for(action_class)
    return McpAuthorizationDecision(True, "authorized", selected_approval)
