from __future__ import annotations

import asyncio
import logging
import shutil
import threading
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from .chat_context_telemetry import ChatContextTelemetry
from .config import Settings
from .mcp_upstream import UpstreamMcpManager
from .models import (
    ApprovalRequest,
    AutonomyPolicy,
    ChatContext,
    ExecutionPermit,
    RecoveryLoop,
)
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
        chat_context_telemetry: ChatContextTelemetry | None = None,
    ) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self.outbox = outbox
        self.upstream_mcp_manager = upstream_mcp_manager
        self.chat_context_telemetry = chat_context_telemetry or ChatContextTelemetry()
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
                snapshot["chat_context_active_count"] = int(
                    db.scalar(
                        select(func.count())
                        .select_from(ChatContext)
                        .where(ChatContext.state == "active")
                    )
                    or 0
                )
                snapshot["federation"] = (
                    self.upstream_mcp_manager.readiness_snapshot(db)
                )
            snapshot["chat_context_telemetry"] = self.chat_context_telemetry.snapshot()
            snapshot["storage"] = self._storage_snapshot()
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
        storage = dict(metrics.get("storage") or {})
        chat_context = dict(metrics.get("chat_context_telemetry") or {})
        chat_context_allocations = dict(chat_context.get("allocations") or {})
        chat_context_resolutions = dict(chat_context.get("resolutions") or {})
        chat_context_rejections = dict(chat_context.get("rejections") or {})
        lines = [
            "# HELP gateway_outbox_events Number of outbox events by status.",
            "# TYPE gateway_outbox_events gauge",
        ]
        for status, value in sorted(counts.items()):
            lines.append(f'gateway_outbox_events{{status="{status}"}} {int(value)}')
        lines.extend(
            [
                "# HELP gateway_outbox_counts_estimated 1 when outbox status counts are planner estimates.",
                "# TYPE gateway_outbox_counts_estimated gauge",
                "gateway_outbox_counts_estimated "
                + ("1" if metrics.get("outbox_counts_estimated") else "0"),
            ]
        )
        lines.extend(
            [
                "# HELP gateway_chat_context_allocations_total Chat-context allocation attempts by bounded result.",
                "# TYPE gateway_chat_context_allocations_total counter",
            ]
        )
        for result, value in sorted(chat_context_allocations.items()):
            lines.append(
                f'gateway_chat_context_allocations_total{{result="{result}"}} {int(value)}'
            )
        lines.extend(
            [
                "# HELP gateway_chat_context_allocation_retries_total Alias allocation retries caused by bounded collision checks.",
                "# TYPE gateway_chat_context_allocation_retries_total counter",
                "gateway_chat_context_allocation_retries_total "
                + str(int(chat_context.get("allocation_retries") or 0)),
                "# HELP gateway_chat_context_resolution_total Alias resolution attempts by bounded result.",
                "# TYPE gateway_chat_context_resolution_total counter",
            ]
        )
        for result, value in sorted(chat_context_resolutions.items()):
            lines.append(
                f'gateway_chat_context_resolution_total{{result="{result}"}} {int(value)}'
            )
        lines.extend(
            [
                "# HELP gateway_chat_context_rejections_total MCP chat-context admission rejections by bounded reason.",
                "# TYPE gateway_chat_context_rejections_total counter",
            ]
        )
        for reason, value in sorted(chat_context_rejections.items()):
            lines.append(
                f'gateway_chat_context_rejections_total{{reason="{reason}"}} {int(value)}'
            )
        lines.extend(
            [
                "# HELP gateway_chat_context_rotations_total Alias rotations completed by this Gateway process.",
                "# TYPE gateway_chat_context_rotations_total counter",
                f'gateway_chat_context_rotations_total {int(chat_context.get("rotations") or 0)}',
                "# HELP gateway_chat_context_active_count Current active durable chat contexts.",
                "# TYPE gateway_chat_context_active_count gauge",
                f'gateway_chat_context_active_count {int(metrics.get("chat_context_active_count") or 0)}',
            ]
        )
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
                "# HELP gateway_storage_monitor_available 1 when the configured storage filesystem is measurable.",
                "# TYPE gateway_storage_monitor_available gauge",
                f"gateway_storage_monitor_available {1 if storage.get('available') else 0}",
                "# HELP gateway_storage_disk_usage_ratio Fraction of monitored storage bytes in use.",
                "# TYPE gateway_storage_disk_usage_ratio gauge",
                f"gateway_storage_disk_usage_ratio {float(storage.get('usage_ratio') or 0.0)}",
                "# HELP gateway_storage_disk_total_bytes Total bytes on the monitored storage filesystem.",
                "# TYPE gateway_storage_disk_total_bytes gauge",
                f"gateway_storage_disk_total_bytes {int(storage.get('total_bytes') or 0)}",
                "# HELP gateway_storage_disk_free_bytes Free bytes on the monitored storage filesystem.",
                "# TYPE gateway_storage_disk_free_bytes gauge",
                f"gateway_storage_disk_free_bytes {int(storage.get('free_bytes') or 0)}",
                "# HELP gateway_storage_disk_watermark 1 when the monitored storage usage ratio reached the named threshold.",
                "# TYPE gateway_storage_disk_watermark gauge",
                f'gateway_storage_disk_watermark{{level="warning"}} {1 if storage.get("warning") else 0}',
                f'gateway_storage_disk_watermark{{level="critical"}} {1 if storage.get("critical") else 0}',
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

    def _storage_snapshot(self) -> dict[str, Any]:
        path = self.settings.gateway_storage_monitor_path
        try:
            usage = shutil.disk_usage(path)
        except OSError as error:
            logger.warning(
                "gateway_storage_monitor_unavailable path=%s error=%s",
                path,
                type(error).__name__,
            )
            return {
                "available": False,
                "path": path,
                "total_bytes": 0,
                "used_bytes": 0,
                "free_bytes": 0,
                "usage_ratio": 0.0,
                "warning": False,
                "critical": False,
            }
        total_bytes = int(usage.total)
        used_bytes = int(usage.used)
        free_bytes = int(usage.free)
        usage_ratio = (
            (total_bytes - free_bytes) / total_bytes if total_bytes > 0 else 0.0
        )
        return {
            "available": True,
            "path": path,
            "total_bytes": total_bytes,
            "used_bytes": used_bytes,
            "free_bytes": free_bytes,
            "usage_ratio": usage_ratio,
            "warning": usage_ratio >= self.settings.gateway_storage_warning_usage_ratio,
            "critical": usage_ratio >= self.settings.gateway_storage_critical_usage_ratio,
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
            "outbox_counts_estimated": False,
            "outbox_counts_source": "empty",
            "pending_total": 0,
            "dead_letter_total": 0,
            "oldest_pending_age_seconds": 0.0,
            "online_replicas": 0,
            "online_realtime_routes": 0,
            "chat_context_active_count": 0,
            "chat_context_telemetry": self.chat_context_telemetry.snapshot(),
            "storage": {
                "available": False,
                "path": self.settings.gateway_storage_monitor_path,
                "total_bytes": 0,
                "used_bytes": 0,
                "free_bytes": 0,
                "usage_ratio": 0.0,
                "warning": False,
                "critical": False,
            },
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
            "storage",
            "chat_context_telemetry",
        ):
            copied[key] = dict(copied.get(key) or {})
        chat_context = copied["chat_context_telemetry"]
        for key in ("allocations", "resolutions", "rejections"):
            chat_context[key] = dict(chat_context.get(key) or {})
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
