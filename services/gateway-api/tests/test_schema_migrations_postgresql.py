from __future__ import annotations

import json
import os
import queue
import threading
import time
import uuid
from collections.abc import Iterator

import pytest
from alembic import command
from gateway_api import schema_migrations
from gateway_api.config import Settings
from gateway_api.schema_migrations import (
    HEAD_REVISION,
    alembic_config,
    get_migration_status,
    revision_is_forward,
    run_schema_migrations,
)
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.engine import make_url

POSTGRES_URL = os.getenv("GATEWAY_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="GATEWAY_TEST_POSTGRES_URL is required for PostgreSQL migration tests",
)

PROD_REVISION = "20260727_0011"
ONLINE_INDEX_SQL = {
    "ix_outbox_events_ready_claim": (
        "CREATE INDEX ix_outbox_events_ready_claim ON outbox_events "
        "(available_at, created_at, id) WHERE status IN ('pending', 'retry')"
    ),
    "ix_outbox_events_stale_claim": (
        "CREATE INDEX ix_outbox_events_stale_claim ON outbox_events "
        "(locked_at, id) "
        "WHERE status = 'processing' AND locked_at IS NOT NULL"
    ),
    "ix_outbox_events_active_created_at": (
        "CREATE INDEX ix_outbox_events_active_created_at ON outbox_events "
        "(created_at, id) WHERE status IN ('pending', 'retry', 'processing')"
    ),
    "ix_agent_tool_calls_lup_pending_schedule": (
        "CREATE INDEX ix_agent_tool_calls_lup_pending_schedule "
        "ON agent_tool_calls (created_at, id) "
        "WHERE traffic_delivery_status = 'pending'"
    ),
}
CAPACITY_INDEX_DROPS = (
    "ix_outbox_events_audit_event_id",
    "ix_outbox_events_published_at",
    "ix_outbox_events_lock_token",
    "ix_outbox_events_locked_by",
    "ix_outbox_events_subject",
    "ix_outbox_events_replayed_from_id",
)


@pytest.fixture
def pg_engine() -> Iterator[Engine]:
    assert POSTGRES_URL is not None
    base_url = make_url(POSTGRES_URL)
    database_name = f"gateway_r2_{uuid.uuid4().hex}"
    admin_engine = create_engine(
        base_url.set(database="postgres"),
        isolation_level="AUTOCOMMIT",
    )
    quoted_name = admin_engine.dialect.identifier_preparer.quote(database_name)
    with admin_engine.connect() as connection:
        connection.exec_driver_sql(f"CREATE DATABASE {quoted_name}")
    target_engine = create_engine(base_url.set(database=database_name))
    try:
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


def _prepare_prod_revision(engine: Engine) -> None:
    config = alembic_config(str(engine.url))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        try:
            with connection.begin():
                command.upgrade(config, PROD_REVISION)
        finally:
            config.attributes.pop("connection", None)
    # The current bootstrap baseline intentionally contains the newest expand
    # schema. Remove those additions to reproduce the actual Release 1 database.
    with engine.begin() as connection:
        for name in ONLINE_INDEX_SQL:
            connection.exec_driver_sql(f'DROP INDEX IF EXISTS "{name}"')
        connection.exec_driver_sql(
            "ALTER TABLE agent_tool_calls "
            "DROP COLUMN IF EXISTS traffic_next_attempt_at, "
            "DROP COLUMN IF EXISTS traffic_last_attempt_at"
        )
        connection.exec_driver_sql(
            "ALTER TABLE agent_tool_calls DROP CONSTRAINT IF EXISTS "
            "ck_agent_tool_calls_traffic_delivery_status"
        )
        connection.exec_driver_sql(
            "ALTER TABLE agent_tool_calls ADD CONSTRAINT "
            "ck_agent_tool_calls_traffic_delivery_status CHECK "
            "(traffic_delivery_status IN "
            "('not_recorded', 'pending', 'delivered', 'disabled'))"
        )


def _revision(engine: Engine) -> str:
    status = get_migration_status(engine)
    assert status.current_revision is not None
    return status.current_revision


def _index_states(engine: Engine) -> dict[str, bool]:
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT index_class.relname, index_state.indisvalid "
                "FROM pg_index AS index_state "
                "JOIN pg_class AS index_class "
                "ON index_class.oid = index_state.indexrelid "
                "WHERE index_class.relname = ANY(:names)"
            ),
            {"names": list(ONLINE_INDEX_SQL)},
        )
        return {str(name): bool(valid) for name, valid in rows}


def _capacity_indexes_present(engine: Engine) -> set[str]:
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT index_class.relname "
                "FROM pg_index AS index_state "
                "JOIN pg_class AS index_class "
                "ON index_class.oid = index_state.indexrelid "
                "WHERE index_class.relname = ANY(:names)"
            ),
            {"names": list(CAPACITY_INDEX_DROPS)},
        )
        return {str(name) for (name,) in rows}


def _create_valid_indexes(engine: Engine) -> None:
    with engine.begin() as connection:
        for statement in ONLINE_INDEX_SQL.values():
            connection.exec_driver_sql(statement)


def _thread_result(target) -> tuple[threading.Thread, queue.Queue[BaseException | None]]:
    results: queue.Queue[BaseException | None] = queue.Queue()

    def run() -> None:
        try:
            target()
        except BaseException as error:  # noqa: BLE001 - asserted by the caller
            results.put(error)
        else:
            results.put(None)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, results


def _wait_for_backend(engine: Engine, pattern: str, timeout: float = 15.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with engine.connect() as connection:
            pid = connection.execute(
                text(
                    "SELECT pid FROM pg_stat_activity "
                    "WHERE datname = current_database() "
                    "AND pid <> pg_backend_pid() AND state = 'active' "
                    "AND query LIKE :pattern ORDER BY query_start LIMIT 1"
                ),
                {"pattern": pattern},
            ).scalar_one_or_none()
        if pid is not None:
            return int(pid)
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for PostgreSQL backend: {pattern}")


def test_first_run_creates_online_indexes_and_retry_is_idempotent(
    pg_engine: Engine,
) -> None:
    _prepare_prod_revision(pg_engine)

    first = run_schema_migrations(pg_engine)
    second = run_schema_migrations(pg_engine)

    assert first.current_revision == HEAD_REVISION
    assert {item.name: item.action for item in first.online_index_operations} == {
        **{name: "created" for name in ONLINE_INDEX_SQL},
        **{name: "dropped" for name in CAPACITY_INDEX_DROPS},
    }
    assert second.online_index_operations == ()
    assert _index_states(pg_engine) == {name: True for name in ONLINE_INDEX_SQL}
    assert _capacity_indexes_present(pg_engine) == set()


def test_existing_valid_indexes_are_reused(pg_engine: Engine) -> None:
    _prepare_prod_revision(pg_engine)
    _create_valid_indexes(pg_engine)

    result = run_schema_migrations(pg_engine)

    assert {item.name: item.action for item in result.online_index_operations} == {
        **{name: "reused" for name in ONLINE_INDEX_SQL},
        **{name: "dropped" for name in CAPACITY_INDEX_DROPS},
    }
    assert _capacity_indexes_present(pg_engine) == set()


def test_previously_absent_capacity_index_is_accepted(pg_engine: Engine) -> None:
    _prepare_prod_revision(pg_engine)
    absent_name = CAPACITY_INDEX_DROPS[0]
    with pg_engine.begin() as connection:
        connection.exec_driver_sql(f'DROP INDEX "{absent_name}"')

    result = run_schema_migrations(pg_engine)

    actions = {item.name: item.action for item in result.online_index_operations}
    assert actions[absent_name] == "absent"
    for name in CAPACITY_INDEX_DROPS[1:]:
        assert actions[name] == "dropped"
    assert _capacity_indexes_present(pg_engine) == set()
    unique_constraints = {
        item["name"] for item in inspect(pg_engine).get_unique_constraints("outbox_events")
    }
    assert "uq_outbox_event_audit_event" in unique_constraints


def test_matching_invalid_index_is_rebuilt(pg_engine: Engine) -> None:
    _prepare_prod_revision(pg_engine)
    with pg_engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO agent_tool_calls "
            "(id, owner_subject, tool_name, arguments, status, "
            "traffic_delivery_status, traffic_attempt_count, created_at) "
            "SELECT md5(value::text), 'user', 'tool', '{}'::json, 'success', "
            "'pending', 0, now() - (value * interval '1 second') "
            "FROM generate_series(1, 50000) AS value"
        )
        connection.exec_driver_sql(ONLINE_INDEX_SQL["ix_outbox_events_ready_claim"])
        connection.exec_driver_sql(ONLINE_INDEX_SQL["ix_outbox_events_stale_claim"])

    blocker = pg_engine.connect()
    transaction = blocker.begin()
    blocker.exec_driver_sql(
        "INSERT INTO agent_tool_calls "
        "(id, owner_subject, tool_name, arguments, status, "
        "traffic_delivery_status, traffic_attempt_count, created_at) VALUES "
        "('blocked-writer', 'user', 'tool', '{}'::json, 'success', "
        "'pending', 0, now())"
    )
    pid_queue: queue.Queue[int] = queue.Queue()

    def build_index() -> None:
        with pg_engine.connect().execution_options(
            isolation_level="AUTOCOMMIT"
        ) as connection:
            pid_queue.put(int(connection.exec_driver_sql("SELECT pg_backend_pid()").scalar_one()))
            connection.exec_driver_sql(
                ONLINE_INDEX_SQL[
                    "ix_agent_tool_calls_lup_pending_schedule"
                ].replace("CREATE INDEX ", "CREATE INDEX CONCURRENTLY ", 1)
            )

    thread, result_queue = _thread_result(build_index)
    pid = pid_queue.get(timeout=5)
    deadline = time.monotonic() + 15
    phase = None
    while time.monotonic() < deadline:
        with pg_engine.connect() as connection:
            phase = connection.execute(
                text(
                    "SELECT phase FROM pg_stat_progress_create_index "
                    "WHERE pid = :pid"
                ),
                {"pid": pid},
            ).scalar_one_or_none()
        if phase == "waiting for writers before build":
            break
        time.sleep(0.05)
    assert phase == "waiting for writers before build"
    with pg_engine.begin() as connection:
        assert connection.execute(
            text("SELECT pg_cancel_backend(:pid)"), {"pid": pid}
        ).scalar_one() is True
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert result_queue.get_nowait() is not None
    transaction.rollback()
    blocker.close()
    assert _index_states(pg_engine)[
        "ix_agent_tool_calls_lup_pending_schedule"
    ] is False

    result = run_schema_migrations(pg_engine)

    actions = {item.name: item.action for item in result.online_index_operations}
    assert actions["ix_agent_tool_calls_lup_pending_schedule"] == "rebuilt"
    assert _index_states(pg_engine) == {name: True for name in ONLINE_INDEX_SQL}


def test_mismatched_index_definition_is_refused(pg_engine: Engine) -> None:
    _prepare_prod_revision(pg_engine)
    with pg_engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE INDEX ix_outbox_events_ready_claim "
            "ON outbox_events (created_at, id) "
            "WHERE status IN ('pending', 'retry')"
        )

    with pytest.raises(RuntimeError, match="definition drift"):
        run_schema_migrations(pg_engine)

    assert _revision(pg_engine) == PROD_REVISION
    columns = [
        item["name"]
        for item in inspect(pg_engine).get_indexes("outbox_events")
        if item["name"] == "ix_outbox_events_ready_claim"
    ]
    assert columns == ["ix_outbox_events_ready_claim"]


def test_online_index_timeout_preserves_transactional_revision(
    pg_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_prod_revision(pg_engine)
    settings = Settings(
        gateway_db_online_index_timeout_seconds=1,
        gateway_db_migration_lock_timeout_seconds=5,
    )
    monkeypatch.setattr(schema_migrations, "get_settings", lambda: settings)
    blocker = pg_engine.connect()
    transaction = blocker.begin()
    blocker.exec_driver_sql("LOCK TABLE outbox_events IN ACCESS EXCLUSIVE MODE")

    with pytest.raises(Exception, match="statement timeout"):
        run_schema_migrations(pg_engine)

    transaction.rollback()
    blocker.close()
    assert _revision(pg_engine) == PROD_REVISION


def test_interrupted_online_build_preserves_revision(pg_engine: Engine) -> None:
    _prepare_prod_revision(pg_engine)
    blocker = pg_engine.connect()
    transaction = blocker.begin()
    blocker.exec_driver_sql("LOCK TABLE outbox_events IN ACCESS EXCLUSIVE MODE")
    thread, result_queue = _thread_result(lambda: run_schema_migrations(pg_engine))
    pid = _wait_for_backend(pg_engine, "CREATE TEMP TABLE gateway_index_probe%")
    with pg_engine.begin() as connection:
        assert connection.execute(
            text("SELECT pg_terminate_backend(:pid)"), {"pid": pid}
        ).scalar_one() is True
    thread.join(timeout=10)
    transaction.rollback()
    blocker.close()

    assert not thread.is_alive()
    assert result_queue.get_nowait() is not None
    assert _revision(pg_engine) == PROD_REVISION


def test_advisory_lock_contention_fails_closed(
    pg_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_prod_revision(pg_engine)
    settings = Settings(gateway_db_migration_lock_timeout_seconds=1)
    monkeypatch.setattr(schema_migrations, "get_settings", lambda: settings)
    blocker = pg_engine.connect()
    blocker.execute(
        text("SELECT pg_advisory_lock(:key)"),
        {"key": settings.gateway_db_migration_advisory_lock_key},
    )
    blocker.commit()

    with pytest.raises(Exception, match="statement timeout"):
        run_schema_migrations(pg_engine)

    blocker.execute(
        text("SELECT pg_advisory_unlock(:key)"),
        {"key": settings.gateway_db_migration_advisory_lock_key},
    )
    blocker.commit()
    blocker.close()
    assert _revision(pg_engine) == PROD_REVISION


def test_transactional_failure_after_online_indexes_is_retryable(
    pg_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_prod_revision(pg_engine)

    def fail_upgrade(*_args, **_kwargs) -> None:
        raise RuntimeError("injected transactional migration failure")

    monkeypatch.setattr(schema_migrations.command, "upgrade", fail_upgrade)
    with pytest.raises(RuntimeError, match="injected transactional"):
        run_schema_migrations(pg_engine)

    assert _revision(pg_engine) == PROD_REVISION
    assert _index_states(pg_engine) == {name: True for name in ONLINE_INDEX_SQL}


def test_expand_migration_preserves_release_one_slot_contract(
    pg_engine: Engine,
) -> None:
    _prepare_prod_revision(pg_engine)
    inspector = inspect(pg_engine)
    old_columns = {
        table: {item["name"] for item in inspector.get_columns(table)}
        for table in inspector.get_table_names()
    }
    old_indexes = {
        table: {item["name"] for item in inspector.get_indexes(table)}
        for table in inspector.get_table_names()
    }

    run_schema_migrations(pg_engine)
    current_inspector = inspect(pg_engine)
    for table, columns in old_columns.items():
        assert columns <= {
            item["name"] for item in current_inspector.get_columns(table)
        }
        current_indexes = {
            item["name"] for item in current_inspector.get_indexes(table)
        }
        allowed_removed_indexes = (
            set(CAPACITY_INDEX_DROPS) if table == "outbox_events" else set()
        )
        assert old_indexes[table] - allowed_removed_indexes <= current_indexes
        assert allowed_removed_indexes.isdisjoint(current_indexes)
    new_columns = {
        item["name"]: item for item in current_inspector.get_columns("agent_tool_calls")
    }
    assert new_columns["traffic_next_attempt_at"]["nullable"] is True
    assert new_columns["traffic_last_attempt_at"]["nullable"] is True
    with pg_engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO agent_tool_calls "
            "(id, owner_subject, tool_name, arguments, status, "
            "traffic_delivery_status, traffic_attempt_count, created_at) VALUES "
            "('old-slot-call', 'old-slot-user', 'tool', '{}'::json, 'success', "
            "'not_recorded', 0, now())"
        )
    assert revision_is_forward(_revision(pg_engine), PROD_REVISION) is True


def test_postgresql_planner_selects_partial_claim_indexes(
    pg_engine: Engine,
) -> None:
    _prepare_prod_revision(pg_engine)
    run_schema_migrations(pg_engine)
    with pg_engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO audit_events "
            "(id, event_type, actor_subject, action, resource_type, status, "
            "payload, created_at) "
            "SELECT md5('audit-' || value::text), 'event', 'user', 'action', "
            "'resource', 'success', '{}'::json, now() "
            "FROM generate_series(1, 10000) AS value"
        )
        connection.exec_driver_sql(
            "INSERT INTO outbox_events "
            "(id, audit_event_id, owner_subject, event_type, subject, payload, "
            "headers, status, attempt_count, max_attempts, available_at, "
            "locked_at, replay_count, created_at, updated_at) "
            "SELECT md5('outbox-' || value::text), "
            "md5('audit-' || value::text), 'user', 'event', 'subject', "
            "'{}'::json, '{}'::json, "
            "CASE WHEN value %% 2 = 0 THEN 'pending' ELSE 'processing' END, "
            "0, 10, now() - interval '1 minute', "
            "CASE WHEN value %% 2 = 0 THEN NULL "
            "WHEN value < 100 THEN now() - interval '1 hour' ELSE now() END, "
            "0, now() - (value * interval '1 second'), now() "
            "FROM generate_series(1, 10000) AS value"
        )
        connection.exec_driver_sql(
            "INSERT INTO agent_tool_calls "
            "(id, owner_subject, tool_name, arguments, status, "
            "traffic_delivery_status, traffic_attempt_count, "
            "traffic_next_attempt_at, created_at) "
            "SELECT md5('call-' || value::text), 'user', 'tool', '{}'::json, "
            "'success', 'pending', 0, now() - interval '1 minute', "
            "now() - (value * interval '1 second') "
            "FROM generate_series(1, 10000) AS value"
        )
        connection.exec_driver_sql("ANALYZE outbox_events")
        connection.exec_driver_sql("ANALYZE agent_tool_calls")
        connection.exec_driver_sql("SET LOCAL enable_seqscan TO off")
        ready_plan = connection.exec_driver_sql(
            "EXPLAIN (FORMAT JSON) SELECT id FROM outbox_events "
            "WHERE status IN ('pending', 'retry') AND available_at <= now() "
            "ORDER BY available_at, created_at, id LIMIT 25 "
            "FOR UPDATE SKIP LOCKED"
        ).scalar_one()
        stale_plan = connection.exec_driver_sql(
            "EXPLAIN (FORMAT JSON) SELECT id FROM outbox_events "
            "WHERE status = 'processing' AND locked_at IS NOT NULL "
            "AND locked_at <= now() - interval '5 minutes'"
        ).scalar_one()
        lup_plan = connection.exec_driver_sql(
            "EXPLAIN (FORMAT JSON) SELECT id FROM agent_tool_calls "
            "WHERE traffic_delivery_status = 'pending' "
            "AND (traffic_next_attempt_at IS NULL "
            "OR traffic_next_attempt_at <= now()) "
            "ORDER BY created_at, id LIMIT 25 FOR UPDATE SKIP LOCKED"
        ).scalar_one()

    assert "ix_outbox_events_ready_claim" in json.dumps(ready_plan)
    assert "ix_outbox_events_stale_claim" in json.dumps(stale_plan)
    assert "ix_agent_tool_calls_lup_pending_schedule" in json.dumps(lup_plan)
