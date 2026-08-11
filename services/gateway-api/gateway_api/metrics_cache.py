from __future__ import annotations

import asyncio
import logging
import threading
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings
from .mcp_upstream import UpstreamMcpManager
from .models import ApprovalRequest, AutonomyPolicy, ExecutionPermit, RecoveryLoop
from .outbox import OutboxService

logger = logging.getLogger(__name__)

POLICY_STATUSES = ("active", "paused", "disabled")
APPROVAL_STATUSES = ("pending", "approved", "rejected", "expired", "revoked")
PERMIT_STATUSES = ("active", "claimed", "consumed", "expired", "revoked")
RECOVERY_STATUSES = (
    "planned",
    "waiting",
    "running",
    "paused",
    "succeeded",
    "exhausted",
    "cancelled",
)


class GatewayMetricsCache:
    """Refresh database-backed metrics off the request event loop."""

    def __init__(
        self,
        *,
        settings: Settings,
        session_factory: sessionmaker,
        outbox: OutboxService,
        upstream_mcp_manager: UpstreamMcpManager,
    ) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self.outbox = outbox
        self.upstream_mcp_manager = upstream_mcp_manager
        self._state_lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        self._snapshot = self._empty_snapshot()
        self._last_success_monotonic: float | None = None
        self._last_success_at: datetime | None = None
        self._refresh_failures = 0
        self._last_error_code: str | None = None
        self._stopping = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="gateway-metrics-cache")

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
            with self.session_factory() as db:
                self._bound_statement_timeout(db)
                snapshot = self.outbox.metrics(db)
                snapshot["autonomy_policies"] = self._status_counts(
                    db, AutonomyPolicy, POLICY_STATUSES
                )
                snapshot["autonomy_approvals"] = self._status_counts(
                    db, ApprovalRequest, APPROVAL_STATUSES
                )
                snapshot["autonomy_permits"] = self._status_counts(
                    db, ExecutionPermit, PERMIT_STATUSES
                )
                snapshot["autonomy_recoveries"] = self._status_counts(
                    db, RecoveryLoop, RECOVERY_STATUSES
                )
                snapshot["federation"] = (
                    self.upstream_mcp_manager.readiness_snapshot(db)
                )
            now = datetime.now(UTC)
            with self._state_lock:
                self._snapshot = snapshot
                self._last_success_monotonic = time.monotonic()
                self._last_success_at = now
                self._last_error_code = None
            return True
        except Exception as error:
            with self._state_lock:
                self._refresh_failures += 1
                self._last_error_code = type(error).__name__[:128]
            logger.exception("gateway_metrics_refresh_failed")
            return False
        finally:
            self._refresh_lock.release()

    def snapshot(self) -> dict[str, Any]:
        with self._state_lock:
            snapshot = self._copy_snapshot(self._snapshot)
            refreshed = self._last_success_monotonic
            refreshed_at = self._last_success_at
            failures = self._refresh_failures
            error_code = self._last_error_code
        age = max(0.0, time.monotonic() - refreshed) if refreshed else 0.0
        stale = refreshed is None or age > self.settings.gateway_metrics_max_stale_seconds
        snapshot.update(
            {
                "metrics_cache_age_seconds": age,
                "metrics_cache_stale": stale,
                "metrics_refresh_failures_total": failures,
                "metrics_last_success_at": (
                    refreshed_at.isoformat() if refreshed_at is not None else None
                ),
                "metrics_last_success_timestamp_seconds": (
                    refreshed_at.timestamp() if refreshed_at is not None else 0.0
                ),
                "metrics_last_error_code": error_code,
                "metrics_refresh_in_progress": self._refresh_lock.locked(),
            }
        )
        return snapshot

    def prometheus(self) -> str:
        metrics = self.snapshot()
        counts = dict(metrics.get("outbox") or {})
        lines = [
            "# HELP gateway_outbox_events Number of outbox events by status.",
            "# TYPE gateway_outbox_events gauge",
        ]
        for status, value in sorted(counts.items()):
            lines.append(f'gateway_outbox_events{{status="{status}"}} {int(value)}')
        for metric_name, help_text, statuses in (
            (
                "gateway_autonomy_policies",
                "Number of autonomy policies by status.",
                metrics["autonomy_policies"],
            ),
            (
                "gateway_autonomy_approvals",
                "Number of approval requests by status.",
                metrics["autonomy_approvals"],
            ),
            (
                "gateway_autonomy_permits",
                "Number of execution permits by status.",
                metrics["autonomy_permits"],
            ),
            (
                "gateway_autonomy_recoveries",
                "Number of recovery loops by status.",
                metrics["autonomy_recoveries"],
            ),
        ):
            lines.extend([f"# HELP {metric_name} {help_text}", f"# TYPE {metric_name} gauge"])
            for status, value in statuses.items():
                lines.append(f'{metric_name}{{status="{status}"}} {int(value)}')
        lines.extend(
            [
                "# TYPE gateway_autonomy_worker_enabled gauge",
                f"gateway_autonomy_worker_enabled {1 if self.settings.gateway_autonomy_enabled else 0}",
                "# TYPE gateway_autonomy_emergency_stop gauge",
                f"gateway_autonomy_emergency_stop {1 if self.settings.gateway_autonomy_emergency_stop else 0}",
                "# TYPE gateway_outbox_oldest_pending_age_seconds gauge",
                f"gateway_outbox_oldest_pending_age_seconds {float(metrics['oldest_pending_age_seconds'])}",
                "# TYPE gateway_outbox_dead_letter_total gauge",
                f"gateway_outbox_dead_letter_total {int(metrics['dead_letter_total'])}",
                "# TYPE gateway_replicas_online gauge",
                f"gateway_replicas_online {int(metrics['online_replicas'])}",
                "# TYPE gateway_realtime_routes_online gauge",
                f"gateway_realtime_routes_online {int(metrics['online_realtime_routes'])}",
                "# TYPE gateway_metrics_cache_age_seconds gauge",
                f"gateway_metrics_cache_age_seconds {float(metrics['metrics_cache_age_seconds'])}",
                "# TYPE gateway_metrics_cache_stale gauge",
                f"gateway_metrics_cache_stale {1 if metrics['metrics_cache_stale'] else 0}",
                "# TYPE gateway_metrics_refresh_failures_total counter",
                f"gateway_metrics_refresh_failures_total {int(metrics['metrics_refresh_failures_total'])}",
                "# TYPE gateway_metrics_refresh_in_progress gauge",
                f"gateway_metrics_refresh_in_progress {1 if metrics['metrics_refresh_in_progress'] else 0}",
                "# TYPE gateway_metrics_cache_last_success_timestamp_seconds gauge",
                "gateway_metrics_cache_last_success_timestamp_seconds "
                + str(metrics["metrics_last_success_timestamp_seconds"]),
                "# TYPE gateway_runtime_info gauge",
                (
                    'gateway_runtime_info{replica_id="'
                    + str(metrics["replica_id"]).replace('"', "")
                    + '",broker_backend="'
                    + str(metrics["broker_backend"]).replace('"', "")
                    + '"} 1'
                ),
            ]
        )
        federation = dict(metrics.get("federation") or {})
        lines.extend(
            [
                "# TYPE gateway_mcp_servers gauge",
                "# TYPE gateway_mcp_circuits gauge",
                "# TYPE gateway_mcp_catalogs_stale gauge",
            ]
        )
        for status, value in sorted(dict(federation.get("servers") or {}).items()):
            lines.append(f'gateway_mcp_servers{{status="{status}"}} {int(value)}')
        for state, value in sorted(dict(federation.get("circuits") or {}).items()):
            lines.append(f'gateway_mcp_circuits{{state="{state}"}} {int(value)}')
        lines.append(f"gateway_mcp_catalogs_stale {int(federation.get('stale_catalogs') or 0)}")
        lines.extend(self.upstream_mcp_manager.telemetry.prometheus_lines())
        return "\n".join(lines) + "\n"

    def _bound_statement_timeout(self, db: Session) -> None:
        if db.bind is None or db.bind.dialect.name != "postgresql":
            return
        milliseconds = max(
            1000,
            int(self.settings.gateway_metrics_refresh_timeout_seconds * 1000),
        )
        db.execute(text(f"SET LOCAL statement_timeout = '{milliseconds}ms'"))

    @staticmethod
    def _status_counts(
        db: Session, model: type, statuses: tuple[str, ...]
    ) -> dict[str, int]:
        return {
            status: int(
                db.scalar(
                    select(func.count()).select_from(model).where(model.status == status)
                )
                or 0
            )
            for status in statuses
        }

    def _empty_snapshot(self) -> dict[str, Any]:
        return {
            "replica_id": self.outbox.replica_id,
            "broker_backend": self.settings.gateway_broker_backend,
            "outbox": {
                status: 0
                for status in (
                    "pending",
                    "retry",
                    "processing",
                    "published",
                    "dead_letter",
                    "cancelled",
                )
            },
            "pending_total": 0,
            "dead_letter_total": 0,
            "oldest_pending_age_seconds": 0.0,
            "online_replicas": 0,
            "online_realtime_routes": 0,
            "autonomy_policies": {status: 0 for status in POLICY_STATUSES},
            "autonomy_approvals": {status: 0 for status in APPROVAL_STATUSES},
            "autonomy_permits": {status: 0 for status in PERMIT_STATUSES},
            "autonomy_recoveries": {status: 0 for status in RECOVERY_STATUSES},
            "federation": {"servers": {}, "circuits": {}, "stale_catalogs": 0},
        }

    @staticmethod
    def _copy_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
        copied = dict(snapshot)
        for key in (
            "outbox",
            "autonomy_policies",
            "autonomy_approvals",
            "autonomy_permits",
            "autonomy_recoveries",
            "federation",
        ):
            copied[key] = dict(copied.get(key) or {})
        return copied

    async def _run(self) -> None:
        while not self._stopping.is_set():
            await asyncio.to_thread(self.refresh_sync)
            try:
                await asyncio.wait_for(
                    self._stopping.wait(),
                    timeout=self.settings.gateway_metrics_refresh_interval_seconds,
                )
            except TimeoutError:
                pass
