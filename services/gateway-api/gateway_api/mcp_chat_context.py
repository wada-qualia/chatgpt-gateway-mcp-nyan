from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from .chat_context import (
    CHAT_CONTEXT_CODE_PATTERN,
    ChatContextAllocationExhausted,
    ChatContextClosed,
    ChatContextDisabled,
    ChatContextExpired,
    ChatContextNotFound,
    ChatContextService,
    ChatContextValidationError,
)
from .config import Settings

CHAT_CONTEXT_ARGUMENT = "chat_context"
CHAT_CONTEXT_CONTRACT_VERSION = 1
CHAT_CONTEXT_MODES = frozenset({"off", "optional", "required"})
CHAT_CONTEXT_EXEMPT_TOOLS = frozenset(
    {"chat_context_start", "chat_context_refresh"}
)
CHAT_CONTEXT_PATTERN = CHAT_CONTEXT_CODE_PATTERN.pattern
CHAT_CONTEXT_ARGUMENT_DESCRIPTION = (
    "ATLAS chat context code for the current conversation. "
    "This is not an authentication credential."
)


class McpChatContextError(RuntimeError):
    pass


class McpChatContextReservedArgumentCollision(McpChatContextError):
    pass


@dataclass(frozen=True, slots=True)
class McpChatContextAdmissionError(McpChatContextError):
    error_code: str
    message: str
    recovery_tool: str
    retry_original_call: bool = True

    def payload(self) -> dict[str, Any]:
        return {
            "error": self.message,
            "error_code": self.error_code,
            "recovery_tool": self.recovery_tool,
            "retry_original_call": self.retry_original_call,
        }


@dataclass(frozen=True, slots=True)
class McpChatContextAdmission:
    mode: str
    arguments: dict[str, Any]
    context_id: str | None = None
    code: str | None = None


def validate_chat_context_mode(mode: str) -> str:
    normalized = str(mode or "").strip().lower()
    if normalized not in CHAT_CONTEXT_MODES:
        raise ValueError(
            "chat_context_mode must be off, optional, or required"
        )
    return normalized


def chat_context_initialize_metadata(mode: str) -> dict[str, Any]:
    return {
        "contract_version": CHAT_CONTEXT_CONTRACT_VERSION,
        "mode": validate_chat_context_mode(mode),
        "pattern": CHAT_CONTEXT_PATTERN,
        "bootstrap_tool": "chat_context_start",
        "refresh_tool": "chat_context_refresh",
    }


def tool_declares_reserved_chat_context(tool: dict[str, Any]) -> bool:
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return False
    properties = schema.get("properties")
    return isinstance(properties, dict) and CHAT_CONTEXT_ARGUMENT in properties


def decorate_public_tool(tool: dict[str, Any], mode: str) -> dict[str, Any]:
    resolved_mode = validate_chat_context_mode(mode)
    projected = copy.deepcopy(tool)
    name = str(projected.get("name") or "")
    if resolved_mode == "off" or name in CHAT_CONTEXT_EXEMPT_TOOLS:
        return projected
    if tool_declares_reserved_chat_context(projected):
        raise McpChatContextReservedArgumentCollision(
            f"tool {name!r} declares reserved top-level argument "
            f"{CHAT_CONTEXT_ARGUMENT!r}"
        )
    schema = projected.get("inputSchema")
    if not isinstance(schema, dict):
        schema = {"type": "object", "properties": {}}
        projected["inputSchema"] = schema
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        properties = {}
    schema["properties"] = {
        CHAT_CONTEXT_ARGUMENT: {
            "type": "string",
            "pattern": CHAT_CONTEXT_PATTERN,
            "description": CHAT_CONTEXT_ARGUMENT_DESCRIPTION,
        },
        **properties,
    }
    required = [
        str(value)
        for value in schema.get("required") or []
        if str(value) != CHAT_CONTEXT_ARGUMENT
    ]
    if resolved_mode == "required":
        required.insert(0, CHAT_CONTEXT_ARGUMENT)
    if required:
        schema["required"] = required
    else:
        schema.pop("required", None)
    return projected


def decorate_public_tools(
    tools: list[dict[str, Any]],
    mode: str,
) -> list[dict[str, Any]]:
    return [decorate_public_tool(tool, mode) for tool in tools]


def chat_context_tool_definitions() -> list[dict[str, Any]]:
    common_annotations = {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    }
    return [
        {
            "name": "chat_context_start",
            "description": (
                "Create an ATLAS chat context code for this conversation. "
                "Use the returned code on subsequent ATLAS tool calls."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "ok": {"type": "boolean"},
                    "error": {"type": ["string", "null"]},
                    "chat_context": {
                        "type": "string",
                        "pattern": CHAT_CONTEXT_PATTERN,
                    },
                    "expires_at": {"type": "string"},
                    "instruction": {"type": "string"},
                },
                "required": [
                    "ok",
                    "error",
                    "chat_context",
                    "expires_at",
                    "instruction",
                ],
                "additionalProperties": True,
            },
            "annotations": {
                "title": "Start chat context",
                **common_annotations,
            },
        },
        {
            "name": "chat_context_refresh",
            "description": (
                "Refresh or rotate a historical ATLAS chat context code while "
                "preserving the durable conversation identity."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "previous_chat_context": {
                        "type": "string",
                        "pattern": CHAT_CONTEXT_PATTERN,
                    }
                },
                "required": ["previous_chat_context"],
                "additionalProperties": False,
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "ok": {"type": "boolean"},
                    "error": {"type": ["string", "null"]},
                    "chat_context": {
                        "type": "string",
                        "pattern": CHAT_CONTEXT_PATTERN,
                    },
                    "expires_at": {"type": "string"},
                    "rotated": {"type": "boolean"},
                    "instruction": {"type": "string"},
                },
                "required": [
                    "ok",
                    "error",
                    "chat_context",
                    "expires_at",
                    "rotated",
                    "instruction",
                ],
                "additionalProperties": True,
            },
            "annotations": {
                "title": "Refresh chat context",
                **common_annotations,
            },
        },
    ]


def admit_chat_context(
    db: Session,
    settings: Settings,
    *,
    owner_subject: str,
    tool_name: str,
    arguments: dict[str, Any],
    mode: str,
) -> McpChatContextAdmission:
    resolved_mode = validate_chat_context_mode(mode)
    copied = dict(arguments)
    if resolved_mode == "off" or tool_name in CHAT_CONTEXT_EXEMPT_TOOLS:
        return McpChatContextAdmission(mode=resolved_mode, arguments=copied)
    raw_code = copied.pop(CHAT_CONTEXT_ARGUMENT, None)
    if raw_code is None:
        if resolved_mode == "optional":
            return McpChatContextAdmission(mode=resolved_mode, arguments=copied)
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_REQUIRED",
            message="ATLAS chat context is required.",
            recovery_tool="chat_context_start",
        )
    if (
        not isinstance(raw_code, str)
        or CHAT_CONTEXT_CODE_PATTERN.fullmatch(raw_code) is None
    ):
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_INVALID",
            message=(
                "ATLAS chat context must contain exactly four Base62 characters."
            ),
            recovery_tool="chat_context_start",
        )
    service = ChatContextService(settings)
    try:
        lease = service.resolve_alias(
            db,
            owner_subject=owner_subject,
            code=raw_code,
            actor_kind="mcp",
        )
        db.commit()
    except ChatContextNotFound as exc:
        db.rollback()
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_UNKNOWN",
            message="ATLAS chat context was not found.",
            recovery_tool="chat_context_start",
        ) from exc
    except ChatContextExpired as exc:
        db.commit()
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_EXPIRED",
            message="ATLAS chat context has expired.",
            recovery_tool="chat_context_refresh",
        ) from exc
    except ChatContextClosed as exc:
        db.rollback()
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_REVOKED",
            message="ATLAS chat context is no longer active.",
            recovery_tool="chat_context_start",
        ) from exc
    except (ChatContextValidationError, ChatContextDisabled) as exc:
        db.rollback()
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_INVALID",
            message="ATLAS chat context cannot be used.",
            recovery_tool="chat_context_start",
        ) from exc
    return McpChatContextAdmission(
        mode=resolved_mode,
        arguments=copied,
        context_id=lease.context_id,
        code=lease.code,
    )


def start_chat_context(
    db: Session,
    settings: Settings,
    *,
    owner_subject: str,
) -> dict[str, Any]:
    service = ChatContextService(settings)
    try:
        lease = service.start_context(
            db,
            owner_subject=owner_subject,
            actor_kind="mcp",
        )
        db.commit()
    except ChatContextAllocationExhausted as exc:
        db.rollback()
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_ALLOCATION_EXHAUSTED",
            message=(
                "ATLAS chat context allocation is temporarily exhausted."
            ),
            recovery_tool="chat_context_start",
            retry_original_call=False,
        ) from exc
    except (ChatContextValidationError, ChatContextDisabled) as exc:
        db.rollback()
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_INVALID",
            message="ATLAS chat context cannot be created.",
            recovery_tool="chat_context_start",
            retry_original_call=False,
        ) from exc
    return {
        "chat_context": lease.code,
        "expires_at": lease.expires_at.isoformat(),
        "instruction": (
            f'Pass chat_context="{lease.code}" to every ATLAS tool call '
            "in this conversation."
        ),
    }


def refresh_chat_context(
    db: Session,
    settings: Settings,
    *,
    owner_subject: str,
    previous_chat_context: str,
) -> dict[str, Any]:
    service = ChatContextService(settings)
    try:
        lease = service.refresh_alias(
            db,
            owner_subject=owner_subject,
            previous_code=previous_chat_context,
            actor_kind="mcp",
        )
        db.commit()
    except ChatContextNotFound as exc:
        db.rollback()
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_UNKNOWN",
            message="Historical ATLAS chat context was not found.",
            recovery_tool="chat_context_start",
            retry_original_call=False,
        ) from exc
    except ChatContextClosed as exc:
        db.rollback()
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_REVOKED",
            message="ATLAS chat context is no longer active.",
            recovery_tool="chat_context_start",
            retry_original_call=False,
        ) from exc
    except ChatContextAllocationExhausted as exc:
        db.rollback()
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_ALLOCATION_EXHAUSTED",
            message=(
                "ATLAS chat context allocation is temporarily exhausted."
            ),
            recovery_tool="chat_context_refresh",
            retry_original_call=False,
        ) from exc
    except (ChatContextValidationError, ChatContextDisabled) as exc:
        db.rollback()
        raise McpChatContextAdmissionError(
            error_code="CHAT_CONTEXT_INVALID",
            message="ATLAS chat context cannot be refreshed.",
            recovery_tool="chat_context_start",
            retry_original_call=False,
        ) from exc
    return {
        "chat_context": lease.code,
        "expires_at": lease.expires_at.isoformat(),
        "rotated": lease.rotated,
        "instruction": (
            f'Pass chat_context="{lease.code}" to every ATLAS tool call '
            "in this conversation."
        ),
    }
