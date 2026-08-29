from __future__ import annotations

import threading
from collections import Counter
from typing import Any

ALLOCATION_RESULTS = ("success", "exhausted")
RESOLUTION_RESULTS = ("success", "not_found", "expired", "closed", "invalid")
REJECTION_REASONS = (
    "required",
    "invalid",
    "unknown",
    "expired",
    "revoked",
    "allocation_exhausted",
)


class ChatContextTelemetry:
    """Process-local bounded counters for chat-context request outcomes.

    Labels are fixed enumerations. No owner, short alias, raw conversation reference,
    or durable context UUID is accepted by this collector.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._allocations = Counter({result: 0 for result in ALLOCATION_RESULTS})
        self._allocation_retries = 0
        self._resolutions = Counter({result: 0 for result in RESOLUTION_RESULTS})
        self._rejections = Counter({reason: 0 for reason in REJECTION_REASONS})
        self._rotations = 0

    def record_allocation(self, result: str, *, retries: int = 0) -> None:
        if result not in ALLOCATION_RESULTS:
            raise ValueError("unsupported chat-context allocation result")
        if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
            raise ValueError("chat-context allocation retries must be a non-negative integer")
        with self._lock:
            self._allocations[result] += 1
            self._allocation_retries += retries

    def record_resolution(self, result: str) -> None:
        if result not in RESOLUTION_RESULTS:
            raise ValueError("unsupported chat-context resolution result")
        with self._lock:
            self._resolutions[result] += 1

    def record_rejection(self, reason: str) -> None:
        if reason not in REJECTION_REASONS:
            raise ValueError("unsupported chat-context rejection reason")
        with self._lock:
            self._rejections[reason] += 1

    def record_rotation(self) -> None:
        with self._lock:
            self._rotations += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "allocations": dict(self._allocations),
                "allocation_retries": self._allocation_retries,
                "resolutions": dict(self._resolutions),
                "rejections": dict(self._rejections),
                "rotations": self._rotations,
            }
