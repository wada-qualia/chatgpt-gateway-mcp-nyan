from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy.orm import sessionmaker

from .agent_autonomy import AgentAutonomyService, AutonomyWorker
from .broker import EventBroker, create_broker
from .config import Settings
from .outbox import OutboxService, OutboxWorker, resolve_replica_id
from .realtime import RealtimeService
from .usage_accounting import LUP_SDK_VERSION, LupUsageAccountingService

logger = logging.getLogger(__name__)


class GatewayRuntime:
    def __init__(self, *, settings: Settings, session_factory: sessionmaker) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self.replica_id = resolve_replica_id(settings)
        self.broker: EventBroker = create_broker(settings, replica_id=self.replica_id)
        self.outbox = OutboxService(
            session_factory=session_factory,
            broker=self.broker,
            settings=settings,
            replica_id=self.replica_id,
        )
        self.realtime = RealtimeService(
            session_factory=session_factory,
            broker=self.broker,
            settings=settings,
            replica_id=self.replica_id,
        )
        self.worker = OutboxWorker(self.outbox)
        self.autonomy = AgentAutonomyService(settings)
        self.usage_accounting = LupUsageAccountingService(settings)
        self.autonomy_worker = AutonomyWorker(
            service=self.autonomy,
            session_factory=session_factory,
            settings=settings,
        )
        self._stopping = asyncio.Event()
        self._broker_task: asyncio.Task[None] | None = None
        self.started = False

    async def start(self) -> None:
        if self.started:
            return
        self._stopping.clear()
        await self.worker.start()
        await self.autonomy_worker.start()
        if self.settings.gateway_broker_backend == "disabled":
            await self.broker.connect()
            await self.realtime.start()
        else:
            self._broker_task = asyncio.create_task(
                self._supervise_broker(), name="gateway-broker-supervisor"
            )
        self.started = True

    async def stop(self) -> None:
        if not self.started:
            return
        self._stopping.set()
        if self._broker_task is not None:
            self._broker_task.cancel()
            try:
                await self._broker_task
            except asyncio.CancelledError:
                pass
            self._broker_task = None
        await self.autonomy_worker.stop()
        await self.realtime.stop()
        await self.worker.stop()
        await self.broker.close()
        self.started = False

    async def _supervise_broker(self) -> None:
        while not self._stopping.is_set():
            if not self.broker.healthy:
                await self.realtime.stop()
                try:
                    await self.broker.close()
                except Exception:
                    logger.exception(
                        "gateway_broker_cleanup_failed",
                        extra={"replica_id": self.replica_id},
                    )
                try:
                    await self.broker.connect()
                    await self.realtime.start()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception(
                        "gateway_broker_connect_failed",
                        extra={"replica_id": self.replica_id},
                    )
            elif self.realtime._subscription is None:
                try:
                    await self.realtime.start()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception(
                        "gateway_realtime_subscription_failed",
                        extra={"replica_id": self.replica_id},
                    )
            await asyncio.sleep(1)

    def readiness(self) -> dict[str, Any]:
        broker_required = (
            self.settings.gateway_outbox_enabled
            and self.settings.gateway_broker_backend != "disabled"
        )
        broker_healthy = self.broker.healthy
        return {
            "status": "ready"
            if (not broker_required or broker_healthy)
            else "not_ready",
            "replica_id": self.replica_id,
            "release_version": self.settings.gateway_release_version,
            "release_revision": self.settings.gateway_release_revision,
            "deployment_slot": self.settings.gateway_deployment_slot,
            "broker_backend": self.settings.gateway_broker_backend,
            "broker_healthy": broker_healthy,
            "outbox_enabled": self.settings.gateway_outbox_enabled,
            "autonomy_enabled": self.settings.gateway_autonomy_enabled,
            "autonomy_emergency_stop": self.settings.gateway_autonomy_emergency_stop,
            "lup_accounting_enabled": self.settings.gateway_lup_enabled,
            "lup_sdk_version": LUP_SDK_VERSION,
        }
