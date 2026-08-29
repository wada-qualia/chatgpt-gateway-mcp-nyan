from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

_TRACEPARENT = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace_id>[0-9a-f]{32})-"
    r"(?P<span_id>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})$"
)
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_METADATA_KEY = re.compile(r"^[A-Za-z0-9]+$")
_MAX_METADATA_VALUE_LENGTH = 200
_MAX_SOURCE_IDENTIFIER_LENGTH = 4096


@dataclass(frozen=True, slots=True)
class W3CTraceContext:
    trace_id: str
    span_id: str


@dataclass(frozen=True, slots=True)
class LangfuseCorrelationBinding:
    """A content-free projection that is safe to attach to a Langfuse observation."""

    trace_id: str
    session_id: str
    request_ref: str
    tool_call_ref: str | None
    command_session_ref: str | None
    metadata: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "session_id": self.session_id,
            "request_ref": self.request_ref,
            "tool_call_ref": self.tool_call_ref,
            "command_session_ref": self.command_session_ref,
            "metadata": dict(self.metadata),
        }


class LangfuseCorrelationAdapter:
    """Build bounded correlation-only Langfuse attributes from Gateway identifiers.

    The adapter never accepts prompts, responses, tool payloads, credentials, arbitrary
    metadata, or trusted identity claims. Potentially user-controlled identifiers are
    represented by deterministic one-way references before they leave the Gateway.
    """

    metadata_keys = frozenset(
        {
            "gatewaytaskusageid",
            "gatewaycorrelationid",
            "gatewaysessionref",
            "gatewayrequestref",
            "gatewaytoolcallref",
            "gatewaycommandsessionref",
            "gatewaychatcontextid",
        }
    )

    @staticmethod
    def parse_traceparent(value: str | None) -> W3CTraceContext | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        match = _TRACEPARENT.fullmatch(normalized)
        if match is None or match.group("version") == "ff":
            return None
        trace_id = match.group("trace_id")
        span_id = match.group("span_id")
        if trace_id == "0" * 32 or span_id == "0" * 16:
            return None
        return W3CTraceContext(trace_id=trace_id, span_id=span_id)

    @staticmethod
    def validate_trace_id(value: str) -> str:
        normalized = value.strip().lower()
        if _TRACE_ID.fullmatch(normalized) is None or normalized == "0" * 32:
            raise ValueError("trace_id is not a valid non-zero W3C trace identifier")
        return normalized

    def resolve_trace_id(
        self,
        *,
        explicit_trace_id: str | None,
        inbound_traceparent: str | None,
        active_traceparent: str | None,
    ) -> str:
        explicit = (
            self.validate_trace_id(explicit_trace_id)
            if explicit_trace_id is not None
            else None
        )
        inbound = self.parse_traceparent(inbound_traceparent)
        active = self.parse_traceparent(active_traceparent)
        if (
            explicit is not None
            and inbound is not None
            and explicit != inbound.trace_id
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Explicit and active W3C trace identifiers conflict",
            )
        resolved = explicit or (inbound.trace_id if inbound else None)
        resolved = resolved or (active.trace_id if active else None)
        if resolved is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A valid W3C trace identifier is required for LUP correlation",
            )
        return resolved

    @staticmethod
    def request_id_from_traceparent(
        value: str | None, *, expected_trace_id: str | None = None
    ) -> str | None:
        parsed = LangfuseCorrelationAdapter.parse_traceparent(value)
        if parsed is None:
            return None
        if expected_trace_id is not None and parsed.trace_id != expected_trace_id:
            return None
        return parsed.span_id

    @staticmethod
    def _uuid(value: str, *, field: str) -> str:
        try:
            return str(UUID(value))
        except (ValueError, AttributeError) as error:
            raise ValueError(f"{field} must be a UUID") from error

    @staticmethod
    def _reference(kind: str, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"{kind} must be a string")
        if not value or len(value) > _MAX_SOURCE_IDENTIFIER_LENGTH:
            raise ValueError(f"{kind} is empty or exceeds the correlation input limit")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError(f"{kind} contains control characters")
        digest = hashlib.sha256(
            f"gateway-correlation-v1\0{kind}\0{value}".encode()
        ).hexdigest()
        return digest

    @classmethod
    def _validate_metadata(cls, metadata: dict[str, str]) -> dict[str, str]:
        if set(metadata) - cls.metadata_keys:
            raise ValueError("correlation metadata contains a non-allowlisted key")
        for key, value in metadata.items():
            if _METADATA_KEY.fullmatch(key) is None:
                raise ValueError("correlation metadata key is not alphanumeric")
            if not isinstance(value, str) or not value:
                raise ValueError(
                    "correlation metadata values must be non-empty strings"
                )
            if len(value) > _MAX_METADATA_VALUE_LENGTH:
                raise ValueError("correlation metadata value exceeds 200 characters")
            if any(ord(character) < 32 or ord(character) == 127 for character in value):
                raise ValueError("correlation metadata contains control characters")
        return metadata

    def bind(
        self,
        *,
        trace_id: str,
        task_usage_id: str,
        correlation_id: str,
        session_id: str,
        request_id: str,
        tool_call_id: str | None = None,
        command_session_id: str | None = None,
        chat_context_id: str | None = None,
    ) -> LangfuseCorrelationBinding:
        trace_id = self.validate_trace_id(trace_id)
        task_usage_id = self._uuid(task_usage_id, field="task_usage_id")
        correlation_id = self._uuid(correlation_id, field="correlation_id")
        normalized_chat_context_id = (
            self._uuid(chat_context_id, field="chat_context_id")
            if chat_context_id is not None
            else None
        )
        session_ref = self._reference("session", session_id)
        request_ref = self._reference("request", request_id)
        tool_call_ref = (
            self._reference("tool_call", tool_call_id)
            if tool_call_id is not None
            else None
        )
        command_session_ref = (
            self._reference("command_session", command_session_id)
            if command_session_id is not None
            else None
        )
        metadata = {
            "gatewaytaskusageid": task_usage_id,
            "gatewaycorrelationid": correlation_id,
            "gatewaysessionref": session_ref,
            "gatewayrequestref": request_ref,
        }
        if tool_call_ref is not None:
            metadata["gatewaytoolcallref"] = tool_call_ref
        if command_session_ref is not None:
            metadata["gatewaycommandsessionref"] = command_session_ref
        if normalized_chat_context_id is not None:
            metadata["gatewaychatcontextid"] = normalized_chat_context_id
        return LangfuseCorrelationBinding(
            trace_id=trace_id,
            session_id=f"gateway-{session_ref}",
            request_ref=request_ref,
            tool_call_ref=tool_call_ref,
            command_session_ref=command_session_ref,
            metadata=self._validate_metadata(metadata),
        )
