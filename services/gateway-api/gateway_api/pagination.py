from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_
from sqlalchemy.orm import Query


class CursorPage(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    next_cursor: str | None = None
    has_more: bool = False


def bounded_limit(value: int, *, maximum: int = 100) -> int:
    return max(1, min(int(value), maximum))


def encode_cursor(timestamp: datetime, item_id: str) -> str:
    payload = json.dumps(
        {"v": 1, "timestamp": timestamp.isoformat(), "id": item_id},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        if payload.get("v") != 1:
            raise ValueError("unsupported cursor version")
        timestamp = datetime.fromisoformat(str(payload["timestamp"]))
        item_id = str(payload["id"])
        if not item_id:
            raise ValueError("missing cursor id")
        return timestamp, item_id
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=400, detail="Invalid pagination cursor"
        ) from exc


def page_desc(
    query: Query,
    *,
    timestamp_column: Any,
    id_column: Any,
    limit: int,
    cursor: str | None,
) -> tuple[list[Any], str | None, bool]:
    safe_limit = bounded_limit(limit)
    if cursor:
        timestamp, item_id = decode_cursor(cursor)
        query = query.filter(
            or_(
                timestamp_column < timestamp,
                and_(timestamp_column == timestamp, id_column < item_id),
            )
        )
    rows = (
        query.order_by(timestamp_column.desc(), id_column.desc())
        .limit(safe_limit + 1)
        .all()
    )
    has_more = len(rows) > safe_limit
    visible = rows[:safe_limit]
    next_cursor = None
    if has_more and visible:
        row = visible[-1]
        next_cursor = encode_cursor(
            getattr(row, timestamp_column.key),
            str(getattr(row, id_column.key)),
        )
    return visible, next_cursor, has_more
