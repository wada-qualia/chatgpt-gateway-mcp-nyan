from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from gateway_api.cold_history import ColdHistoryClient
from gateway_api.dto import OutboxDeliveryAttemptOut, OutboxEventOut
from gateway_api.models import AuditEvent, OutboxDeliveryAttempt, OutboxEvent, User
from gateway_api.routers.outbox import rehydrate_outbox_event
from gateway_api.schema_migrations import run_schema_migrations
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

POSTGRES_URL = os.getenv("GATEWAY_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="GATEWAY_TEST_POSTGRES_URL is required for PostgreSQL rehydration tests",
)


@pytest.fixture
def pg_engine() -> Iterator[Engine]:
    assert POSTGRES_URL is not None
    base_url = make_url(POSTGRES_URL)
    database_name = f"gateway_rehydrate_{uuid.uuid4().hex}"
    admin_engine = create_engine(
        base_url.set(database="postgres"),
        isolation_level="AUTOCOMMIT",
    )
    quoted_name = admin_engine.dialect.identifier_preparer.quote(database_name)
    with admin_engine.connect() as connection:
        connection.exec_driver_sql(f"CREATE DATABASE {quoted_name}")
    target_engine = create_engine(base_url.set(database=database_name))
    try:
        run_schema_migrations(target_engine)
        yield target_engine
    finally:
        target_engine.dispose()
        with admin_engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :database_name AND pid <> pg_backend_pid()"
                ),
                {"database_name": database_name},
            )
            connection.exec_driver_sql(f"DROP DATABASE {quoted_name}")
        admin_engine.dispose()


def test_postgresql_rehydrate_flushes_parent_before_attempts(pg_engine: Engine) -> None:
    event_id = "pg-rehydrate-event"
    audit_id = "pg-rehydrate-source-audit"
    attempt_id = "pg-rehydrate-attempt"
    created_at = datetime(2026, 7, 19, 19, 48, 12, tzinfo=UTC)
    cold_event = {
        "id": event_id,
        "audit_event_id": audit_id,
        "owner_subject": "test:owner",
        "event_type": "gateway.history.rehydrate.pg-test.v1",
        "subject": "gateway.events.pg-rehydrate-event",
        "payload": {"source": "cold-history"},
        "headers": {"trace": "pg-rehydrate"},
        "status": "published",
        "attempt_count": 1,
        "max_attempts": 10,
        "available_at": created_at.isoformat(),
        "locked_by": None,
        "locked_at": None,
        "published_at": (created_at + timedelta(seconds=1)).isoformat(),
        "broker_stream": "GATEWAY_EVENTS",
        "broker_sequence": 100,
        "last_error": None,
        "replay_count": 0,
        "replayed_from_id": None,
        "created_at": created_at.isoformat(),
        "updated_at": (created_at + timedelta(seconds=1)).isoformat(),
    }
    cold_attempt = {
        "id": attempt_id,
        "outbox_event_id": event_id,
        "attempt_number": 1,
        "replica_id": "gateway-green",
        "status": "published",
        "error": None,
        "broker_stream": "GATEWAY_EVENTS",
        "broker_sequence": 100,
        "started_at": created_at.isoformat(),
        "completed_at": (created_at + timedelta(seconds=1)).isoformat(),
    }

    def history_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == f"/v1/events/{event_id}":
            return httpx.Response(200, json=cold_event)
        if request.url.path == f"/v1/events/{event_id}/attempts":
            return httpx.Response(200, json=[cold_attempt])
        return httpx.Response(404, json={"detail": "not found"})

    async def scenario() -> None:
        async_client = httpx.AsyncClient(
            base_url="https://history.test",
            transport=httpx.MockTransport(history_handler),
        )
        history_client = ColdHistoryClient(
            base_url="https://history.test",
            ca_cert_path="unused",
            client_cert_path="unused",
            client_key_path="unused",
            connect_timeout_seconds=1.0,
            read_timeout_seconds=1.0,
            client=async_client,
        )
        request = SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(cold_history_client=history_client)
            )
        )
        session_factory = sessionmaker(bind=pg_engine, expire_on_commit=False)
        try:
            with session_factory() as session:
                session.add(
                    AuditEvent(
                        id=audit_id,
                        event_type="gateway.history.rehydrate.pg-test.v1",
                        actor_subject="test:producer",
                        action="publish",
                        resource_type="outbox",
                        resource_id=event_id,
                        status="success",
                        payload={},
                        created_at=created_at,
                    )
                )
                session.commit()
                user = User(
                    subject="test:operator",
                    username="operator",
                    roles=["gateway-admin"],
                )
                restored = await rehydrate_outbox_event(
                    event_id,
                    request,
                    user,
                    session,
                )
                assert OutboxEventOut.model_validate(restored) == OutboxEventOut.model_validate(
                    cold_event
                )
                attempts = (
                    session.query(OutboxDeliveryAttempt)
                    .filter(OutboxDeliveryAttempt.outbox_event_id == event_id)
                    .order_by(
                        OutboxDeliveryAttempt.attempt_number,
                        OutboxDeliveryAttempt.id,
                    )
                    .all()
                )
                assert [OutboxDeliveryAttemptOut.model_validate(item) for item in attempts] == [
                    OutboxDeliveryAttemptOut.model_validate(cold_attempt)
                ]
                rehydration_audits = (
                    session.query(AuditEvent)
                    .filter(
                        AuditEvent.event_type == "gateway.outbox.history.rehydrated.v1",
                        AuditEvent.resource_id == event_id,
                    )
                    .all()
                )
                assert len(rehydration_audits) == 1
                repeated = await rehydrate_outbox_event(
                    event_id,
                    request,
                    user,
                    session,
                )
                assert repeated.id == event_id
                assert (
                    session.query(AuditEvent)
                    .filter(
                        AuditEvent.event_type == "gateway.outbox.history.rehydrated.v1",
                        AuditEvent.resource_id == event_id,
                    )
                    .count()
                    == 1
                )
                assert session.get(OutboxEvent, event_id) is not None
                assert session.get(OutboxDeliveryAttempt, attempt_id) is not None
        finally:
            await history_client.close()

    asyncio.run(scenario())
