from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .config import Settings

BrokerCallback = Callable[[str, bytes, dict[str, str]], Awaitable[None]]


@dataclass(frozen=True)
class BrokerPublishAck:
    stream: str | None
    sequence: int | None
    duplicate: bool = False


class EventBroker(Protocol):
    @property
    def healthy(self) -> bool: ...

    async def connect(self) -> None: ...

    async def close(self) -> None: ...

    async def publish(
        self,
        subject: str,
        payload: bytes,
        *,
        message_id: str,
        headers: dict[str, str],
    ) -> BrokerPublishAck: ...

    async def subscribe(self, subject: str, callback: BrokerCallback) -> Any: ...

    async def subscribe_durable(
        self,
        subject: str,
        *,
        durable: str,
        callback: BrokerCallback,
        batch_size: int = 50,
    ) -> Any: ...


class DisabledBroker:
    @property
    def healthy(self) -> bool:
        return True

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def publish(
        self,
        subject: str,
        payload: bytes,
        *,
        message_id: str,
        headers: dict[str, str],
    ) -> BrokerPublishAck:
        raise RuntimeError("Event broker is disabled")

    async def subscribe(self, subject: str, callback: BrokerCallback) -> None:
        return None

    async def subscribe_durable(
        self,
        subject: str,
        *,
        durable: str,
        callback: BrokerCallback,
        batch_size: int = 50,
    ) -> None:
        return None


class InMemoryBroker:
    def __init__(self, *, stream: str = "MEMORY") -> None:
        self.stream = stream
        self.connected = False
        self.published: list[dict[str, Any]] = []
        self._seen: set[str] = set()
        self._subscriptions: list[tuple[str, BrokerCallback]] = []

    @property
    def healthy(self) -> bool:
        return self.connected

    async def connect(self) -> None:
        self.connected = True

    async def close(self) -> None:
        self.connected = False
        self._subscriptions.clear()

    @staticmethod
    def _matches(pattern: str, subject: str) -> bool:
        pattern_parts = pattern.split(".")
        subject_parts = subject.split(".")
        for index, item in enumerate(pattern_parts):
            if item == ">":
                return True
            if index >= len(subject_parts):
                return False
            if item not in {"*", subject_parts[index]}:
                return False
        return len(pattern_parts) == len(subject_parts)

    async def publish(
        self,
        subject: str,
        payload: bytes,
        *,
        message_id: str,
        headers: dict[str, str],
    ) -> BrokerPublishAck:
        if not self.connected:
            raise RuntimeError("In-memory broker is not connected")
        duplicate = message_id in self._seen
        if not duplicate:
            self._seen.add(message_id)
            self.published.append(
                {
                    "subject": subject,
                    "payload": payload,
                    "message_id": message_id,
                    "headers": dict(headers),
                }
            )
        callbacks = [
            callback
            for pattern, callback in self._subscriptions
            if self._matches(pattern, subject)
        ]
        if callbacks:
            await asyncio.gather(
                *(callback(subject, payload, dict(headers)) for callback in callbacks)
            )
        return BrokerPublishAck(
            stream=self.stream,
            sequence=len(self.published),
            duplicate=duplicate,
        )

    async def subscribe(self, subject: str, callback: BrokerCallback) -> tuple[str, BrokerCallback]:
        subscription = (subject, callback)
        self._subscriptions.append(subscription)
        return subscription

    async def subscribe_durable(
        self,
        subject: str,
        *,
        durable: str,
        callback: BrokerCallback,
        batch_size: int = 50,
    ) -> tuple[str, BrokerCallback]:
        return await self.subscribe(subject, callback)


class NatsJetStreamBroker:
    def __init__(self, settings: Settings, *, replica_id: str) -> None:
        self.settings = settings
        self.replica_id = replica_id
        self._connection: Any = None
        self._jetstream: Any = None
        self._subscriptions: list[Any] = []
        self._consumer_tasks: list[asyncio.Task[None]] = []

    @property
    def healthy(self) -> bool:
        return bool(self._connection is not None and self._connection.is_connected)

    async def connect(self) -> None:
        import nats

        self._connection = await nats.connect(
            servers=self.settings.nats_servers,
            name=f"gateway-api-{self.replica_id}",
            connect_timeout=5,
            reconnect_time_wait=1,
            max_reconnect_attempts=-1,
        )
        self._jetstream = self._connection.jetstream(timeout=5)
        try:
            await self._jetstream.stream_info(self.settings.gateway_nats_stream)
        except Exception as exc:
            if exc.__class__.__name__ not in {"NotFoundError", "NoStreamResponseError"}:
                raise
            await self._jetstream.add_stream(
                name=self.settings.gateway_nats_stream,
                subjects=[f"{self.settings.gateway_nats_subject_prefix.strip('.')}.>"],
            )

    async def close(self) -> None:
        for task in self._consumer_tasks:
            task.cancel()
        for task in self._consumer_tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._consumer_tasks.clear()
        for subscription in self._subscriptions:
            try:
                await subscription.unsubscribe()
            except Exception:
                pass
        self._subscriptions.clear()
        if self._connection is not None and not self._connection.is_closed:
            await self._connection.drain()
            await self._connection.close()
        self._connection = None
        self._jetstream = None

    async def publish(
        self,
        subject: str,
        payload: bytes,
        *,
        message_id: str,
        headers: dict[str, str],
    ) -> BrokerPublishAck:
        if self._jetstream is None:
            raise RuntimeError("NATS JetStream broker is not connected")
        publish_headers = dict(headers)
        publish_headers["Nats-Msg-Id"] = message_id
        ack = await self._jetstream.publish(
            subject,
            payload,
            headers=publish_headers,
            stream=self.settings.gateway_nats_stream,
        )
        return BrokerPublishAck(
            stream=getattr(ack, "stream", self.settings.gateway_nats_stream),
            sequence=getattr(ack, "seq", None),
            duplicate=bool(getattr(ack, "duplicate", False)),
        )

    async def subscribe(self, subject: str, callback: BrokerCallback) -> Any:
        if self._connection is None:
            raise RuntimeError("NATS broker is not connected")

        async def handler(message: Any) -> None:
            await callback(
                message.subject,
                bytes(message.data),
                {str(key): str(value) for key, value in dict(message.headers or {}).items()},
            )

        subscription = await self._connection.subscribe(subject, cb=handler)
        self._subscriptions.append(subscription)
        return subscription

    async def subscribe_durable(
        self,
        subject: str,
        *,
        durable: str,
        callback: BrokerCallback,
        batch_size: int = 50,
    ) -> asyncio.Task[None]:
        if self._jetstream is None:
            raise RuntimeError("NATS JetStream broker is not connected")
        subscription = await self._jetstream.pull_subscribe(
            subject,
            durable=durable,
            stream=self.settings.gateway_nats_stream,
        )
        self._subscriptions.append(subscription)

        async def consume() -> None:
            from nats.errors import TimeoutError as NatsTimeoutError

            while True:
                try:
                    messages = await subscription.fetch(
                        max(1, min(int(batch_size), 500)), timeout=1
                    )
                except NatsTimeoutError:
                    continue
                for message in messages:
                    try:
                        await callback(
                            message.subject,
                            bytes(message.data),
                            {
                                str(key): str(value)
                                for key, value in dict(message.headers or {}).items()
                            },
                        )
                    except Exception:
                        await message.nak()
                    else:
                        await message.ack()

        task = asyncio.create_task(
            consume(), name=f"nats-durable-consumer-{durable}"
        )
        self._consumer_tasks.append(task)
        return task


def create_broker(settings: Settings, *, replica_id: str) -> EventBroker:
    if settings.gateway_broker_backend == "memory":
        return InMemoryBroker(stream=settings.gateway_nats_stream)
    if settings.gateway_broker_backend == "nats":
        return NatsJetStreamBroker(settings, replica_id=replica_id)
    return DisabledBroker()
