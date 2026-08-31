from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlparse

from .mcp_federation_policy import canonical_json, sha256_json

_SECRET_KEY = re.compile(
    r"(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|password|credential|authorization|cookie|private[_-]?key|api[_-]?key)",
    re.IGNORECASE,
)
_ROLE_TAG = re.compile(
    r"</?(?:system|developer|assistant|user|tool)(?:\s[^<>]{0,500})?>",
    re.IGNORECASE,
)
_INJECTION_PHRASE = re.compile(
    r"\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions?\b",
    re.IGNORECASE,
)
_SIZE = re.compile(r"^(?:any|[1-9][0-9]{0,4}x[1-9][0-9]{0,4})$")
_ALLOWED_MEDIA = {
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
    "audio/mpeg",
    "audio/wav",
    "audio/ogg",
    "application/pdf",
    "application/octet-stream",
    "text/plain",
    "text/markdown",
    "application/json",
}
_ALLOWED_INLINE_ICON_MEDIA = {"image/png", "image/jpeg", "image/webp", "image/gif"}
_ALLOWED_URI_SCHEMES = {"https", "mcp", "urn"}


class RichFidelityError(ValueError):
    def __init__(self, code: str, message: str, *, http_status: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


@dataclass(frozen=True, slots=True)
class RichResultProjection:
    model_payload: dict[str, Any]
    client_meta: dict[str, Any]
    truncated: bool
    serialized_bytes: int
    media_bytes: int


def _text(value: Any, *, maximum: int, neutralize_instructions: bool = False) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = "".join(
        "\n"
        if char == "\n"
        else "\t"
        if char == "\t"
        else ""
        if unicodedata.category(char).startswith("C")
        else char
        for char in text.replace("\r\n", "\n").replace("\r", "\n")
    )
    if neutralize_instructions:
        text = _ROLE_TAG.sub("[untrusted-role-tag]", text)
        text = _INJECTION_PHRASE.sub("[untrusted-instruction]", text)
    lines = [" ".join(line.split()) for line in text.split("\n")]
    text = "\n".join(line for line in lines if line).strip()
    return text[:maximum]


def sanitize_server_instructions(value: Any) -> str:
    return _text(value, maximum=12000, neutralize_instructions=True)


def sanitize_title(value: Any) -> str | None:
    return _text(value, maximum=240) or None


def sanitize_description(value: Any) -> str:
    return _text(value, maximum=4000)


def _reject_secret_keys(value: Any, *, path: str = "$", depth: int = 0) -> None:
    if depth > 20:
        raise RichFidelityError(
            "MCP_METADATA_INVALID", "MCP metadata nesting is too deep"
        )
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            if _SECRET_KEY.search(key_text):
                raise RichFidelityError(
                    "MCP_SECRET_MATERIAL_REJECTED",
                    f"Secret-shaped MCP metadata field is not allowed at {path}.{key_text}",
                )
            _reject_secret_keys(child, path=f"{path}.{key_text}", depth=depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, path=f"{path}[{index}]", depth=depth + 1)


def _bounded_json(value: Any, *, maximum_bytes: int, label: str) -> Any:
    try:
        canonical = json.loads(canonical_json(value))
    except (TypeError, ValueError) as exc:
        raise RichFidelityError(
            "MCP_METADATA_INVALID", f"{label} is not valid JSON metadata"
        ) from exc
    encoded = canonical_json(canonical).encode("utf-8")
    if len(encoded) > maximum_bytes:
        raise RichFidelityError(
            "MCP_METADATA_TOO_LARGE", f"{label} exceeds the metadata limit"
        )
    _reject_secret_keys(canonical)
    return canonical


def normalize_annotations(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RichFidelityError("MCP_METADATA_INVALID", "Annotations must be an object")
    allowed = {
        "title",
        "readOnlyHint",
        "destructiveHint",
        "idempotentHint",
        "openWorldHint",
        "audience",
        "priority",
    }
    normalized: dict[str, Any] = {}
    for key, raw in value.items():
        if key not in allowed:
            continue
        if key == "title":
            title = sanitize_title(raw)
            if title:
                normalized[key] = title
        elif key in {
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        }:
            if isinstance(raw, bool):
                normalized[key] = raw
        elif key == "audience":
            if isinstance(raw, list):
                audience = [item for item in raw if item in {"user", "assistant"}]
                if audience:
                    normalized[key] = list(dict.fromkeys(audience))
        elif key == "priority":
            if isinstance(raw, (int, float)) and 0 <= float(raw) <= 1:
                normalized[key] = float(raw)
    return _bounded_json(normalized, maximum_bytes=16384, label="annotations")


def normalize_execution(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RichFidelityError(
            "MCP_METADATA_INVALID", "Tool execution must be an object"
        )
    task_support = value.get("taskSupport")
    if task_support is None:
        return {}
    if task_support not in {"forbidden", "optional", "required"}:
        raise RichFidelityError(
            "MCP_METADATA_INVALID", "Tool execution.taskSupport is invalid"
        )
    return {"taskSupport": task_support}


def _decode_data_uri(src: str, *, maximum_bytes: int) -> tuple[str, int]:
    match = re.fullmatch(r"data:([^;,]+);base64,([A-Za-z0-9+/=\s]+)", src)
    if match is None:
        raise RichFidelityError(
            "MCP_ICON_INVALID", "Inline icon must be a base64 data URI"
        )
    mime = match.group(1).lower()
    if mime not in _ALLOWED_INLINE_ICON_MEDIA:
        raise RichFidelityError(
            "MCP_ICON_INVALID", "Inline icon MIME type is not allowed"
        )
    try:
        decoded = base64.b64decode(match.group(2), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RichFidelityError(
            "MCP_ICON_INVALID", "Inline icon base64 is invalid"
        ) from exc
    if len(decoded) > maximum_bytes:
        raise RichFidelityError(
            "MCP_ICON_INVALID", "Inline icon exceeds the size limit"
        )
    return mime, len(decoded)


def normalize_icons(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 8:
        raise RichFidelityError("MCP_ICON_INVALID", "Tool icons must be a bounded list")
    result: list[dict[str, Any]] = []
    for raw in value:
        if not isinstance(raw, dict):
            raise RichFidelityError("MCP_ICON_INVALID", "Tool icon must be an object")
        src = str(raw.get("src") or "").strip()
        if not src or len(src) > 4096:
            raise RichFidelityError("MCP_ICON_INVALID", "Tool icon src is invalid")
        mime = str(raw.get("mimeType") or "").lower() or None
        if src.startswith("data:"):
            detected, _ = _decode_data_uri(src, maximum_bytes=32768)
            if mime and mime != detected:
                raise RichFidelityError(
                    "MCP_ICON_INVALID", "Tool icon MIME type mismatch"
                )
            mime = detected
        else:
            parsed = urlparse(src)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.fragment
            ):
                raise RichFidelityError(
                    "MCP_ICON_INVALID", "Tool icon URL must be safe HTTPS"
                )
        sizes_raw = raw.get("sizes")
        sizes: list[str] | None = None
        if sizes_raw is not None:
            if not isinstance(sizes_raw, list) or len(sizes_raw) > 8:
                raise RichFidelityError(
                    "MCP_ICON_INVALID", "Tool icon sizes are invalid"
                )
            sizes = []
            for item in sizes_raw:
                size = str(item)
                if not _SIZE.fullmatch(size):
                    raise RichFidelityError(
                        "MCP_ICON_INVALID", "Tool icon size is invalid"
                    )
                if size not in sizes:
                    sizes.append(size)
        icon: dict[str, Any] = {"src": src}
        if mime:
            icon["mimeType"] = mime
        if sizes:
            icon["sizes"] = sizes
        result.append(icon)
    return result


def normalize_component_meta(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RichFidelityError("MCP_METADATA_INVALID", "Tool _meta must be an object")
    return _bounded_json(value, maximum_bytes=65536, label="tool _meta")


def normalize_tool_descriptor(
    *,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any] | None,
    title: Any,
    description: Any,
    annotations: Any,
    icons: Any,
    execution: Any,
    component_meta: Any,
) -> dict[str, Any]:
    return {
        "input": input_schema,
        "output": output_schema,
        "title": sanitize_title(title),
        "description": sanitize_description(description),
        "annotations": normalize_annotations(annotations),
        "icons": normalize_icons(icons),
        "execution": normalize_execution(execution),
        "component_meta": normalize_component_meta(component_meta),
    }


def tool_descriptor_hash(descriptor: dict[str, Any]) -> str:
    return sha256_json(descriptor)


def sdk_tool_descriptor(tool: Any) -> dict[str, Any]:
    annotations = (
        tool.annotations.model_dump(mode="json", by_alias=True, exclude_none=True)
        if getattr(tool, "annotations", None)
        else {}
    )
    icons = [
        item.model_dump(mode="json", by_alias=True, exclude_none=True)
        for item in (tool.icons or [])
    ]
    execution = (
        tool.execution.model_dump(mode="json", by_alias=True, exclude_none=True)
        if getattr(tool, "execution", None)
        else {}
    )
    return {
        "input": dict(tool.input_schema or {}),
        "output": dict(tool.output_schema) if tool.output_schema else None,
        "title": getattr(tool, "title", None),
        "description": tool.description or "",
        "annotations": annotations,
        "icons": icons,
        "execution": execution,
        "component_meta": dict(getattr(tool, "meta", None) or {}),
    }


def _safe_uri(value: Any) -> str:
    uri = str(value or "").strip()
    if not uri or len(uri) > 4096:
        raise RichFidelityError("MCP_RESOURCE_INVALID", "Resource URI is invalid")
    parsed = urlparse(uri)
    if parsed.scheme.lower() not in _ALLOWED_URI_SCHEMES:
        raise RichFidelityError(
            "MCP_RESOURCE_INVALID", "Resource URI scheme is not allowed"
        )
    if parsed.username or parsed.password or parsed.fragment:
        raise RichFidelityError(
            "MCP_RESOURCE_INVALID", "Resource URI contains unsafe parts"
        )
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if _SECRET_KEY.search(key):
            raise RichFidelityError(
                "MCP_RESOURCE_INVALID", "Resource URI contains secret-shaped query data"
            )
    return uri


def _decode_media(data: Any, *, mime: str, maximum_bytes: int) -> tuple[str, int]:
    if mime not in _ALLOWED_MEDIA:
        raise RichFidelityError(
            "MCP_MEDIA_INVALID", "MCP media MIME type is not allowed"
        )
    text = str(data or "")
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RichFidelityError(
            "MCP_MEDIA_INVALID", "MCP media base64 is invalid"
        ) from exc
    if len(decoded) > maximum_bytes:
        raise RichFidelityError(
            "MCP_MEDIA_TOO_LARGE",
            "MCP media exceeds the per-item limit",
            http_status=413,
        )
    return text, len(decoded)


def _content_id(item: dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(item).encode("utf-8")).hexdigest()
    return f"urn:gateway-mcp-content:{digest[:32]}"


def project_call_result(
    payload: dict[str, Any],
    *,
    max_text_bytes: int,
    max_result_bytes: int,
    max_content_items: int,
    max_media_item_bytes: int = 524288,
    max_client_meta_bytes: int = 65536,
) -> RichResultProjection:
    if not isinstance(payload, dict):
        raise RichFidelityError(
            "MCP_PROTOCOL_MISMATCH", "MCP result must be an object", http_status=502
        )
    structured = payload.get("structuredContent")
    if structured is not None:
        if not isinstance(structured, dict):
            raise RichFidelityError(
                "MCP_PROTOCOL_MISMATCH",
                "structuredContent must be an object",
                http_status=502,
            )
        _reject_secret_keys(structured, path="$.structuredContent")
        try:
            structured = _bounded_json(
                structured, maximum_bytes=max_result_bytes, label="structuredContent"
            )
        except RichFidelityError as exc:
            if exc.code != "MCP_METADATA_TOO_LARGE":
                raise
            raise RichFidelityError(
                "MCP_RESULT_TOO_LARGE",
                "Upstream MCP result exceeds the Gateway result limit",
                http_status=413,
            ) from exc
    content = payload.get("content")
    if not isinstance(content, list):
        raise RichFidelityError(
            "MCP_PROTOCOL_MISMATCH",
            "MCP result content must be a list",
            http_status=502,
        )
    truncated = len(content) > max_content_items
    selected = content[:max_content_items]
    text_budget = max_text_bytes
    model_content: list[dict[str, Any]] = []
    client_content_meta: dict[str, Any] = {}
    media_bytes = 0
    for raw in selected:
        if not isinstance(raw, dict):
            raise RichFidelityError(
                "MCP_PROTOCOL_MISMATCH",
                "MCP content item must be an object",
                http_status=502,
            )
        item_type = str(raw.get("type") or "")
        annotations = normalize_annotations(raw.get("annotations"))
        item_meta = normalize_component_meta(raw.get("_meta", raw.get("meta")))
        item: dict[str, Any]
        if item_type == "text":
            text = str(raw.get("text") or "")
            encoded = text.encode("utf-8")
            if len(encoded) > text_budget:
                text = encoded[: max(text_budget, 0)].decode("utf-8", errors="ignore")
                truncated = True
                text_budget = 0
            else:
                text_budget -= len(encoded)
            item = {"type": "text", "text": text}
        elif item_type in {"image", "audio"}:
            mime = str(raw.get("mimeType") or "").lower()
            data, decoded_size = _decode_media(
                raw.get("data"), mime=mime, maximum_bytes=max_media_item_bytes
            )
            media_bytes += decoded_size
            item = {"type": item_type, "data": data, "mimeType": mime}
        elif item_type == "resource_link":
            name = _text(raw.get("name"), maximum=255)
            if not name:
                raise RichFidelityError(
                    "MCP_RESOURCE_INVALID", "Resource link name is required"
                )
            item = {
                "type": "resource_link",
                "name": name,
                "uri": _safe_uri(raw.get("uri")),
            }
            title = sanitize_title(raw.get("title"))
            description = sanitize_description(raw.get("description"))
            if title:
                item["title"] = title
            if description:
                item["description"] = description
            mime = str(raw.get("mimeType") or "").lower()
            if mime:
                if mime not in _ALLOWED_MEDIA:
                    raise RichFidelityError(
                        "MCP_RESOURCE_INVALID", "Resource MIME type is not allowed"
                    )
                item["mimeType"] = mime
            size = raw.get("size")
            if size is not None:
                if not isinstance(size, int) or size < 0 or size > max_result_bytes:
                    raise RichFidelityError(
                        "MCP_RESOURCE_INVALID", "Resource size is invalid"
                    )
                item["size"] = size
            icons = normalize_icons(raw.get("icons"))
            if icons:
                item["icons"] = icons
        elif item_type == "resource":
            resource = raw.get("resource")
            if not isinstance(resource, dict):
                raise RichFidelityError(
                    "MCP_RESOURCE_INVALID", "Embedded resource must be an object"
                )
            uri = _safe_uri(resource.get("uri"))
            mime = str(resource.get("mimeType") or "").lower() or None
            resource_meta = normalize_component_meta(
                resource.get("_meta", resource.get("meta"))
            )
            projected: dict[str, Any] = {"uri": uri}
            if mime:
                if mime not in _ALLOWED_MEDIA:
                    raise RichFidelityError(
                        "MCP_RESOURCE_INVALID",
                        "Embedded resource MIME type is not allowed",
                    )
                projected["mimeType"] = mime
            if "text" in resource:
                text = str(resource.get("text") or "")
                encoded = text.encode("utf-8")
                if len(encoded) > text_budget:
                    text = encoded[: max(text_budget, 0)].decode(
                        "utf-8", errors="ignore"
                    )
                    truncated = True
                    text_budget = 0
                else:
                    text_budget -= len(encoded)
                projected["text"] = text
            elif "blob" in resource:
                blob, decoded_size = _decode_media(
                    resource.get("blob"),
                    mime=mime or "application/octet-stream",
                    maximum_bytes=max_media_item_bytes,
                )
                projected["blob"] = blob
                media_bytes += decoded_size
            else:
                raise RichFidelityError(
                    "MCP_RESOURCE_INVALID", "Embedded resource has no content"
                )
            item = {"type": "resource", "resource": projected}
            if resource_meta:
                item_meta = {**item_meta, "resource": resource_meta}
        else:
            raise RichFidelityError(
                "MCP_PROTOCOL_MISMATCH",
                f"Unsupported MCP content type: {item_type}",
                http_status=502,
            )
        if annotations:
            item["annotations"] = annotations
        content_id = _content_id(item)
        item["_gateway"] = {"content_id": content_id}
        if item_meta:
            client_content_meta[content_id] = item_meta
        model_content.append(item)
    result_meta = normalize_component_meta(payload.get("_meta", payload.get("meta")))
    client_meta: dict[str, Any] = {}
    if result_meta:
        client_meta["result"] = result_meta
    if client_content_meta:
        client_meta["content"] = client_content_meta
    client_meta = _bounded_json(
        client_meta,
        maximum_bytes=max_client_meta_bytes,
        label="result client-only _meta",
    )
    model_payload: dict[str, Any] = {
        "content": model_content,
        "isError": bool(payload.get("isError", False)),
    }
    if structured is not None:
        model_payload["structuredContent"] = structured
    model_payload["_gateway"] = {
        "truncated": truncated,
        "content_count": len(model_content),
        "client_meta_present": bool(client_meta),
        "client_meta_sha256": sha256_json(client_meta) if client_meta else None,
    }
    serialized = canonical_json(model_payload).encode("utf-8")
    if len(serialized) > max_result_bytes:
        raise RichFidelityError(
            "MCP_RESULT_TOO_LARGE",
            "Upstream MCP result exceeds the Gateway result limit",
            http_status=413,
        )
    return RichResultProjection(
        model_payload=model_payload,
        client_meta=client_meta,
        truncated=truncated,
        serialized_bytes=len(serialized),
        media_bytes=media_bytes,
    )
