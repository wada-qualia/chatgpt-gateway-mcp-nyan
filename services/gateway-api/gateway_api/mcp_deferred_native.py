from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .config import get_settings
from .mcp_federation_broker import (
    AuthorizedRevision,
    mcp_federation_broker_tool_names,
    resolve_authorized_revision,
)
from .mcp_presentation import PresentationContext, public_projection_name
from .mcp_tool_registry import ToolDispatchTarget
from .models import McpServer, McpTool, McpToolRevision, User

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DIRECT_APPROVAL_CLASS = "none"


@dataclass(frozen=True, slots=True)
class DeferredNativeEntry:
    authorized: AuthorizedRevision
    public_name: str
    namespace_name: str
    namespace_description: str


def _bounded_text(value: str | None, *, limit: int) -> str:
    text = _CONTROL_RE.sub("", str(value or ""))
    return " ".join(text.split())[:limit]


def deferred_public_name(item: AuthorizedRevision) -> str:
    base = public_projection_name(
        item.server.normalized_slug,
        item.tool.upstream_name,
        item.exposure.projected_name,
    )
    revision_suffix = item.revision.id.replace("-", "")[:12]
    schema_suffix = item.revision.schema_hash[:16]
    suffix = f"{revision_suffix}_{schema_suffix}"
    prefix = base[: 64 - len(suffix) - 1].rstrip("_") or "tool"
    return f"{prefix}_{suffix}"


def deferred_namespace_name(server: McpServer) -> str:
    return public_projection_name("mcp", server.normalized_slug, f"mcp_{server.normalized_slug}")


def deferred_namespace_description(server: McpServer) -> str:
    namespace_name = deferred_namespace_name(server)
    return _bounded_text(
        f"Gateway-managed namespace {namespace_name}. "
        "Discovery is tenant-scoped and policy-filtered, every call is bound to an exact reviewed revision, "
        "and approval-required actions remain behind the stable broker workflow.",
        limit=700,
    )


def _allowed_by_presentation(
    context: PresentationContext,
    *,
    public_name: str,
    item: AuthorizedRevision,
) -> bool:
    if context.allowed_tool_names is None:
        return True
    identities = {
        public_name,
        item.tool.id,
        item.tool.upstream_name,
        item.tool.normalized_name,
        item.revision.id,
        str(item.exposure.projected_name or ""),
    }
    return bool(identities.intersection(context.allowed_tool_names))


def deferred_entries_for_context(
    db: Session,
    *,
    user: User,
    context: PresentationContext,
) -> list[DeferredNativeEntry]:
    if context.selected_mode != "deferred_native":
        return []
    if not {"deferred_loading", "tool_search"}.issubset(context.capabilities):
        return []
    maximum_direct_tools = get_settings().gateway_mcp_catalog_max_tools
    rows = (
        db.query(McpToolRevision, McpTool, McpServer)
        .join(McpTool, McpTool.id == McpToolRevision.tool_id)
        .join(McpServer, McpServer.id == McpToolRevision.server_id)
        .filter(
            McpToolRevision.owner_subject == user.subject,
            McpTool.owner_subject == user.subject,
            McpServer.owner_subject == user.subject,
            McpTool.lifecycle_state == "active",
            McpTool.current_revision_id == McpToolRevision.id,
        )
        .order_by(
            McpServer.normalized_slug.asc(),
            McpTool.normalized_name.asc(),
            McpToolRevision.revision_number.desc(),
        )
        .limit(maximum_direct_tools * 4)
        .all()
    )
    entries: list[DeferredNativeEntry] = []
    for revision, tool, server in rows:
        tool_ref = f"mcp-tool://{server.id}/{tool.id}/{revision.id}"
        try:
            item = resolve_authorized_revision(
                db,
                user=user,
                tool_ref=tool_ref,
                schema_hash=revision.schema_hash,
                require_available=False,
            )
        except HTTPException:
            continue
        if item.approval_class.value != _DIRECT_APPROVAL_CLASS:
            continue
        public_name = deferred_public_name(item)
        if not _allowed_by_presentation(
            context,
            public_name=public_name,
            item=item,
        ):
            continue
        entries.append(
            DeferredNativeEntry(
                authorized=item,
                public_name=public_name,
                namespace_name=deferred_namespace_name(server),
                namespace_description=deferred_namespace_description(server),
            )
        )
        if len(entries) >= maximum_direct_tools:
            break
    return entries


def deferred_native_tool_definition(entry: DeferredNativeEntry) -> dict[str, Any]:
    item = entry.authorized
    revision = item.revision
    definition: dict[str, Any] = {
        "name": entry.public_name,
        "description": _bounded_text(revision.sanitized_description, limit=1800),
        "inputSchema": revision.input_schema,
        "annotations": dict(revision.annotations or {}),
    }
    if revision.sanitized_title:
        definition["title"] = _bounded_text(revision.sanitized_title, limit=240)
    if revision.output_schema is not None:
        definition["outputSchema"] = revision.output_schema
    return definition


def deferred_native_dispatch_target(entry: DeferredNativeEntry) -> ToolDispatchTarget:
    item = entry.authorized
    return ToolDispatchTarget(
        provider="deferred_native",
        public_name=entry.public_name,
        revision_id=item.revision.id,
        metadata={
            "server_id": item.server.id,
            "tool_id": item.tool.id,
            "exposure_id": item.exposure.id,
            "schema_hash": item.revision.schema_hash,
            "policy_id": item.policy.id,
            "policy_generation": item.policy.generation,
            "exposure_version": item.exposure.version,
            "approval_class": item.approval_class.value,
            "namespace_name": entry.namespace_name,
        },
    )


def resolve_deferred_dispatch(
    db: Session,
    *,
    user: User,
    context: PresentationContext,
    target: ToolDispatchTarget,
) -> AuthorizedRevision:
    if context.selected_mode != "deferred_native":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "MCP_DEFERRED_MODE_STALE",
                "message": "Deferred tool execution requires an active deferred-native presentation context",
            },
        )
    revision_id = str(target.revision_id or "")
    server_id = str(target.metadata.get("server_id") or "")
    tool_id = str(target.metadata.get("tool_id") or "")
    schema_hash = str(target.metadata.get("schema_hash") or "")
    if not revision_id or not server_id or not tool_id or len(schema_hash) != 64:
        raise HTTPException(status_code=409, detail="Deferred tool binding is incomplete")
    item = resolve_authorized_revision(
        db,
        user=user,
        tool_ref=f"mcp-tool://{server_id}/{tool_id}/{revision_id}",
        schema_hash=schema_hash,
        require_available=True,
    )
    expected_name = deferred_public_name(item)
    if (
        expected_name != target.public_name
        or item.exposure.id != str(target.metadata.get("exposure_id") or "")
        or item.policy.id != str(target.metadata.get("policy_id") or "")
        or item.policy.generation != int(target.metadata.get("policy_generation") or 0)
        or item.exposure.version != int(target.metadata.get("exposure_version") or 0)
        or item.approval_class.value != _DIRECT_APPROVAL_CLASS
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "MCP_DEFERRED_TOOL_STALE",
                "message": "The deferred tool binding no longer matches the authorized revision and policy",
                "revision_id": revision_id,
                "schema_hash": schema_hash,
            },
        )
    if not _allowed_by_presentation(
        context,
        public_name=expected_name,
        item=item,
    ):
        raise HTTPException(status_code=403, detail="Deferred tool is outside the presentation allowlist")
    return item


def deferred_native_profile_payload(
    *,
    context: PresentationContext,
    public_base_url: str,
    entries: list[DeferredNativeEntry],
) -> dict[str, Any]:
    broker_names = list(mcp_federation_broker_tool_names())
    deferred_enabled = context.selected_mode == "deferred_native"
    direct_names = [entry.public_name for entry in entries] if deferred_enabled else []
    allowed_tools = [*broker_names, *direct_names]
    never_approval = [name for name in allowed_tools if name != "mcp_action_execute"]
    always_approval = ["mcp_action_execute"]
    namespaces: dict[str, dict[str, Any]] = {}
    for entry in entries if deferred_enabled else []:
        namespace = namespaces.setdefault(
            entry.namespace_name,
            {
                "name": entry.namespace_name,
                "description": entry.namespace_description,
                "direct_read_tools": 0,
            },
        )
        namespace["direct_read_tools"] += 1
    effective_mode = "deferred_native" if deferred_enabled else "catalog_broker"
    namespace_summary = "; ".join(
        f"{value['name']} ({value['direct_read_tools']} direct read tools)"
        for value in sorted(namespaces.values(), key=lambda item: item["name"])[:12]
    )
    server_description = _bounded_text(
        "Gateway-owned MCP federation surface. Tool discovery is tenant-scoped and policy-filtered. "
        "Read-only tools may be loaded as exact revision-bound native definitions; write, destructive, "
        "unknown-risk and production actions remain behind the stable prepare/execute broker workflow."
        + (f" Available Gateway-managed namespaces: {namespace_summary}." if namespace_summary else ""),
        limit=2400,
    )
    mcp_tool = {
        "type": "mcp",
        "server_label": "gateway_federation",
        "server_description": server_description,
        "server_url": f"{public_base_url.rstrip('/')}/mcp",
        "defer_loading": deferred_enabled,
        "allowed_tools": allowed_tools,
        "require_approval": {
            "always": {"tool_names": always_approval},
            "never": {"tool_names": never_approval},
        },
    }
    response_tools: list[dict[str, Any]] = [mcp_tool]
    if deferred_enabled:
        response_tools.append({"type": "tool_search", "execution": "server"})
    return {
        "profile_id": context.profile_id,
        "configured_mode": context.configured_mode,
        "selected_mode": context.selected_mode,
        "effective_mode": effective_mode,
        "selection_reason": context.selection_reason,
        "policy_generation": context.policy_generation,
        "capabilities": sorted(context.capabilities),
        "authorization": {
            "required": True,
            "included": False,
            "source": "caller_supplied_oauth_access_token",
        },
        "responses_api": {"tools": response_tools},
        "namespaces": sorted(namespaces.values(), key=lambda value: value["name"]),
        "direct_tool_count": len(direct_names),
        "broker_tool_count": len(broker_names),
        "invariants": {
            "allowed_tools_server_derived": True,
            "approval_policy_server_derived": True,
            "exact_revision_schema_binding": True,
            "approval_required_actions_use_broker": True,
            "broker_fallback_preserved": True,
        },
    }
