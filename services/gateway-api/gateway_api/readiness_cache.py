from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from .config import Settings
from .mcp_upstream import UpstreamMcpManager
from .schema_migrations import (
    MigrationStatus,
    get_migration_status,
    revision_is_forward,
    validate_schema_metadata,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ReadinessSnapshot:
    migration_status: MigrationStatus
    forward_compatible: bool
    federation: dict[str, Any]
    refreshed_monotonic: float


class ReadinessCache:
    """Single-flight deep readiness validation with a bounded cheap probe."""

    def __init__(
        self,
        *,
        settings: Settings,
        session_factory: sessionmaker,
        upstream_mcp_manager: UpstreamMcpManager,
    ) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self.upstream_mcp_manager = upstream_mcp_manager
        self._state_lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        self._snapshot: ReadinessSnapshot | None = None
        self._last_error_code: str | None = None
        self._refresh_failures = 0
        self._stopping = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def seed(self, migration_status: MigrationStatus) -> None:
        federation = self._federation_snapshot()
        forward_compatible = revision_is_forward(
            migration_status.current_revision,
            migration_status.head_revision,
        )
        with self._state_lock:
            self._snapshot = ReadinessSnapshot(
                migration_status=migration_status,
                forward_compatible=forward_compatible,
                federation=federation,
                refreshed_monotonic=time.monotonic(),
            )
            self._last_error_code = None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(
            self._run(), name="gateway-readiness-cache"
        )

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    def refresh_sync(self) -> bool:
        if not self._refresh_lock.acquire(blocking=False):
            return False
        try:
            migration_status = get_migration_status()
            forward_compatible = revision_is_forward(
                migration_status.current_revision,
                migration_status.head_revision,
            )
            if not migration_status.at_head and not forward_compatible:
                raise RuntimeError(
                    "Database revision is incompatible with the running image"
                )
            validate_schema_metadata()
            federation = self._federation_snapshot()
            snapshot = ReadinessSnapshot(
                migration_status=migration_status,
                forward_compatible=forward_compatible,
                federation=federation,
                refreshed_monotonic=time.monotonic(),
            )
            with self._state_lock:
                self._snapshot = snapshot
                self._last_error_code = None
            return True
        except Exception as error:
            with self._state_lock:
                self._refresh_failures += 1
                self._last_error_code = type(error).__name__[:128]
            logger.exception("gateway_deep_readiness_refresh_failed")
            return False
        finally:
            self._refresh_lock.release()

    def cached(self) -> tuple[ReadinessSnapshot | None, bool, str | None]:
        with self._state_lock:
            snapshot = self._snapshot
            error_code = self._last_error_code
        stale = (
            snapshot is None
            or time.monotonic() - snapshot.refreshed_monotonic
            > self.settings.gateway_readiness_max_stale_seconds
        )
        return snapshot, stale, error_code

    async def probe_database(self) -> bool:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._probe_database_sync),
                timeout=self.settings.gateway_readiness_probe_timeout_seconds,
            )
        except (TimeoutError, SQLAlchemyError):
            return False

    def _probe_database_sync(self) -> bool:
        with self.session_factory() as db:
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                milliseconds = max(
                    100,
                    int(
                        self.settings.gateway_readiness_probe_timeout_seconds
                        * 1000
                    ),
                )
                db.execute(text(f"SET LOCAL statement_timeout = '{milliseconds}ms'"))
            return db.execute(text("SELECT 1")).scalar_one() == 1

    def _federation_snapshot(self) -> dict[str, Any]:
        with self.session_factory() as db:
            return self.upstream_mcp_manager.readiness_snapshot(db)

    async def _run(self) -> None:
        interval = self.settings.gateway_readiness_refresh_interval_seconds
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=interval)
                return
            except TimeoutError:
                pass
            await asyncio.to_thread(self.refresh_sync)
