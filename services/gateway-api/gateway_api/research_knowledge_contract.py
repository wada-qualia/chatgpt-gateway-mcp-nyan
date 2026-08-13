from __future__ import annotations

import json
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class ResearchLink(BaseModel):
    target_note_id: str = Field(min_length=1, max_length=240)
    target_url: str = Field(min_length=1, max_length=4096)
    label: str = Field(min_length=1, max_length=300)


class ResearchSourceReference(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    title: str = Field(min_length=1, max_length=500)
    locator: str | None = Field(default=None, max_length=500)


def _single_line(value: str) -> str:
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())


def validate_reference_url(url: str) -> str:
    value = url.strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https", "obsidian"}:
        raise ValueError("reference URL must use http, https, or obsidian scheme")
    if parsed.scheme in {"http", "https"} and not parsed.netloc:
        raise ValueError("reference URL must include a host")
    if len(value) > 4096:
        raise ValueError("reference URL is too long")
    return value


def _managed_comment_payload(value: dict[str, str | None]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return payload.replace("--", "\\u002d\\u002d")


def render_note_link(link: ResearchLink) -> str:
    payload = _managed_comment_payload(
        {
            "target_note_id": link.target_note_id,
            "target_url": validate_reference_url(link.target_url),
            "label": _single_line(link.label),
        }
    )
    label = _single_line(link.label).replace("]", "\\]")
    url = validate_reference_url(link.target_url).replace(")", "%29")
    return f"<!-- research-link:v1 {payload} -->\n[{label}]({url})"


def render_source_reference(source: ResearchSourceReference) -> str:
    payload = _managed_comment_payload(
        {
            "url": validate_reference_url(source.url),
            "title": _single_line(source.title),
            "locator": _single_line(source.locator) if source.locator else None,
        }
    )
    title = _single_line(source.title).replace("]", "\\]")
    url = validate_reference_url(source.url).replace(")", "%29")
    suffix = f" — {_single_line(source.locator)}" if source.locator else ""
    return f"<!-- research-source:v1 {payload} -->\n- Source: [{title}]({url}){suffix}"
