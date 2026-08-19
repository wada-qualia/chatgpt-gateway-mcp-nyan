from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError

from . import database
from . import models as _models
from .config import get_settings
from .migration_operations import CreateIndexConcurrently, DropIndexConcurrently

BASELINE_REVISION = "20260725_0001"
PROJECTION_REVISION = "20260725_0002"
HEAD_REVISION = "20260818_0014"
LEGACY_ANCHOR_TABLES = {"users", "secret_blobs", "oauth_clients"}
REVISION_PATTERN = re.compile(r"^(?P<date>\d{8})_(?P<sequence>\d{4})$")


@dataclass(frozen=True, slots=True)
class OnlineIndexReceipt:
    name: str
    action: Literal["created", "reused", "rebuilt", "dropped", "absent"]
    valid: bool


@dataclass(frozen=True)
class MigrationPlan:
    current_revision: str | None
    head_revision: str
    pending_revisions: tuple[str, ...]
    compatibility: tuple[str, ...]
    safe_for_live_expand: bool
    online_index_operations: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class MigrationStatus:
    current_revisions: tuple[str, ...]
    head_revision: str
    at_head: bool
    adopted_legacy_schema: bool = False
    online_index_operations: tuple[OnlineIndexReceipt, ...] = ()

    @property
    def current_revision(self) -> str | None:
        if len(self.current_revisions) == 1:
            return self.current_revisions[0]
        return None

    def to_dict(self) -> dict:
        value = asdict(self)
        value["current_revision"] = self.current_revision
        return value


def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def alembic_config(database_url: str | None = None) -> Config:
    root = project_root()
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "database" / "alembic"))
    if database_url is not None:
        config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def migration_head(config: Config | None = None) -> str:
    active_config = config or alembic_config()
    heads = ScriptDirectory.from_config(active_config).get_heads()
    if len(heads) != 1:
        raise RuntimeError(f"Alembic must have exactly one head, found {heads}")
    head = heads[0]
    if head != HEAD_REVISION:
        raise RuntimeError(
            f"Alembic head {head} does not match application head {HEAD_REVISION}"
        )
    return head


def revision_is_forward(current_revision: str | None, required_revision: str) -> bool:
    if current_revision is None:
        return False
    current_match = REVISION_PATTERN.fullmatch(current_revision)
    required_match = REVISION_PATTERN.fullmatch(required_revision)
    if current_match is None or required_match is None:
        return False
    current_order = (
        int(current_match.group("date")),
        int(current_match.group("sequence")),
    )
    required_order = (
        int(required_match.group("date")),
        int(required_match.group("sequence")),
    )
    return current_order > required_order


def _online_operations_for_scripts(
    scripts: Sequence[object],
) -> tuple[CreateIndexConcurrently | DropIndexConcurrently, ...]:
    operations: list[CreateIndexConcurrently | DropIndexConcurrently] = []
    names: set[str] = set()
    for script in scripts:
        declared = getattr(script.module, "online_operations", ())
        if not isinstance(declared, tuple):
            raise TypeError(
                f"Alembic revision {script.revision} online_operations must be a tuple"
            )
        for operation in declared:
            if not isinstance(
                operation, (CreateIndexConcurrently, DropIndexConcurrently)
            ):
                raise TypeError(
                    f"Alembic revision {script.revision} declared an unsupported "
                    "online operation"
                )
            if operation.name in names:
                raise RuntimeError(
                    f"duplicate concurrent index operation: {operation.name}"
                )
            names.add(operation.name)
            operations.append(operation)
    return tuple(operations)


def get_migration_plan(
    target_engine: Engine | None = None,
) -> MigrationPlan:
    active_engine = target_engine if target_engine is not None else database.engine
    config = alembic_config(str(active_engine.url))
    scripts = ScriptDirectory.from_config(config)
    head = migration_head(config)
    with active_engine.connect() as connection:
        current_revisions = _current_revisions(connection)
    if len(current_revisions) > 1:
        raise RuntimeError(
            f"Live deployment requires one database revision, found {current_revisions}"
        )
    current = current_revisions[0] if current_revisions else None
    lower = current or "base"
    pending_scripts = tuple(reversed(tuple(scripts.iterate_revisions(head, lower))))
    pending = tuple(script.revision for script in pending_scripts)
    compatibility = tuple(
        str(getattr(script.module, "deployment_compatibility", "unspecified"))
        for script in pending_scripts
    )
    online_operations = _online_operations_for_scripts(pending_scripts)
    return MigrationPlan(
        current_revision=current,
        head_revision=head,
        pending_revisions=pending,
        compatibility=compatibility,
        safe_for_live_expand=all(value == "expand" for value in compatibility),
        online_index_operations=tuple(item.name for item in online_operations),
    )


def _current_revisions(connection: Connection) -> tuple[str, ...]:
    inspector = inspect(connection)
    if "alembic_version" not in inspector.get_table_names():
        return ()
    rows = connection.execute(
        text("SELECT version_num FROM alembic_version ORDER BY version_num")
    )
    return tuple(str(row[0]) for row in rows)


def _is_empty_database(connection: Connection) -> bool:
    return not {
        table
        for table in inspect(connection).get_table_names()
        if table != "alembic_version"
    }


def _validate_legacy_identity(connection: Connection) -> None:
    tables = set(inspect(connection).get_table_names())
    missing = sorted(LEGACY_ANCHOR_TABLES - tables)
    if missing:
        raise RuntimeError(
            "Refusing to adopt an unversioned database that is not a recognized "
            f"Gateway schema; missing anchor tables: {missing}"
        )
    adoptable_missing_tables = {
        "mcp_projection_generations",
        "mcp_projection_tools",
        "mcp_projection_verifications",
    }
    required_legacy_tables = (
        set(_models.Base.metadata.tables) - adoptable_missing_tables
    )
    missing_legacy_tables = sorted(required_legacy_tables - tables)
    if missing_legacy_tables:
        raise RuntimeError(
            "Refusing to adopt an incomplete legacy Gateway schema; "
            f"missing tables: {missing_legacy_tables}"
        )
    oauth_columns = {
        column["name"]
        for column in inspect(connection).get_columns("oauth_clients")
    }
    required_oauth_columns = {
        "client_id",
        "client_name",
        "redirect_uris",
        "scope",
        "created_at",
    }
    missing_oauth = sorted(required_oauth_columns - oauth_columns)
    if missing_oauth:
        raise RuntimeError(
            "Refusing to adopt an invalid legacy oauth_clients table; "
            f"missing columns: {missing_oauth}"
        )
    for table_name in (
        "mcp_projection_generations",
        "mcp_projection_tools",
        "mcp_projection_verifications",
    ):
        if table_name not in tables:
            continue
        expected = set(_models.Base.metadata.tables[table_name].columns.keys())
        actual = {
            column["name"]
            for column in inspect(connection).get_columns(table_name)
        }
        missing_columns = sorted(expected - actual)
        if missing_columns:
            raise RuntimeError(
                f"Refusing to adopt partial table {table_name}; "
                f"missing columns: {missing_columns}"
            )


def _validate_metadata_schema(connection: Connection) -> None:
    inspector = inspect(connection)
    actual_tables = set(inspector.get_table_names())
    expected_tables = set(_models.Base.metadata.tables)
    missing_tables = sorted(expected_tables - actual_tables)
    if missing_tables:
        raise RuntimeError(f"Database schema is missing tables: {missing_tables}")
    missing_columns: dict[str, list[str]] = {}
    for table_name in sorted(expected_tables):
        expected = set(_models.Base.metadata.tables[table_name].columns.keys())
        actual = {
            column["name"] for column in inspector.get_columns(table_name)
        }
        missing = sorted(expected - actual)
        if missing:
            missing_columns[table_name] = missing
    if missing_columns:
        raise RuntimeError(
            f"Database schema is missing model columns: {missing_columns}"
        )
    oauth_columns = {
        column["name"] for column in inspector.get_columns("oauth_clients")
    }
    required_projection_columns = {
        "presentation_profile",
        "presentation_policy_generation",
        "presentation_mode",
        "presentation_capabilities",
        "workspace_plan",
        "allowed_tool_names",
        "updated_at",
    }
    missing_projection_columns = sorted(
        required_projection_columns - oauth_columns
    )
    if missing_projection_columns:
        raise RuntimeError(
            "oauth_clients is not projection-ready; missing columns: "
            f"{missing_projection_columns}"
        )
    if connection.dialect.name == "postgresql":
        revision_columns = {
            column["name"]
            for column in inspector.get_columns("mcp_tool_revisions")
        }
        if "search_vector" not in revision_columns:
            raise RuntimeError("mcp_tool_revisions.search_vector is missing")
        required_triggers = {
            "trg_mcp_tool_revision_guard",
            "trg_reject_mcp_projection_tool_update",
            "trg_protect_mcp_projection_generation_content",
        }
        trigger_rows = connection.execute(
            text(
                "SELECT tgname FROM pg_trigger "
                "WHERE NOT tgisinternal AND tgname = ANY(:names)"
            ),
            {"names": list(required_triggers)},
        )
        actual_triggers = {str(row[0]) for row in trigger_rows}
        missing_triggers = sorted(required_triggers - actual_triggers)
        if missing_triggers:
            raise RuntimeError(
                f"Database schema is missing migration triggers: {missing_triggers}"
            )


@dataclass(frozen=True, slots=True)
class _IndexSignature:
    method: str
    unique: bool
    nulls_not_distinct: bool
    key_count: int
    columns: tuple[str, ...]
    predicate: str | None
    options: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _IndexState:
    table: str
    valid: bool
    ready: bool
    signature: _IndexSignature


_INDEX_STATE_SQL = text(
    """
    SELECT
        table_class.relname AS table_name,
        access_method.amname AS method_name,
        index_state.indisunique,
        index_state.indnullsnotdistinct,
        index_state.indisvalid,
        index_state.indisready,
        index_state.indnkeyatts,
        ARRAY(
            SELECT pg_get_indexdef(index_state.indexrelid, position, true)
            FROM generate_series(1, index_state.indnatts) AS position
            ORDER BY position
        ) AS key_columns,
        pg_get_expr(index_state.indpred, index_state.indrelid, true) AS predicate,
        COALESCE(index_class.reloptions, ARRAY[]::text[]) AS index_options
    FROM pg_index AS index_state
    JOIN pg_class AS index_class
      ON index_class.oid = index_state.indexrelid
    JOIN pg_class AS table_class
      ON table_class.oid = index_state.indrelid
    JOIN pg_namespace AS namespace
      ON namespace.oid = index_class.relnamespace
    JOIN pg_am AS access_method
      ON access_method.oid = index_class.relam
    WHERE namespace.nspname = :schema_name
      AND index_class.relname = :index_name
    """
)


def _index_state(
    connection: Connection,
    *,
    schema_name: str,
    index_name: str,
) -> _IndexState | None:
    rows = connection.execute(
        _INDEX_STATE_SQL,
        {"schema_name": schema_name, "index_name": index_name},
    ).mappings().all()
    if len(rows) > 1:
        raise RuntimeError(f"concurrent index name is ambiguous: {index_name}")
    if not rows:
        return None
    row = rows[0]
    return _IndexState(
        table=str(row["table_name"]),
        valid=bool(row["indisvalid"]),
        ready=bool(row["indisready"]),
        signature=_IndexSignature(
            method=str(row["method_name"]),
            unique=bool(row["indisunique"]),
            nulls_not_distinct=bool(row["indnullsnotdistinct"]),
            key_count=int(row["indnkeyatts"]),
            columns=tuple(str(item) for item in row["key_columns"]),
            predicate=str(row["predicate"]) if row["predicate"] is not None else None,
            options=tuple(sorted(str(item) for item in row["index_options"])),
        ),
    )


def _quoted_identifier(connection: Connection, value: str) -> str:
    return connection.dialect.identifier_preparer.quote(value)


def _expected_index_signature(
    connection: Connection,
    operation: CreateIndexConcurrently,
) -> _IndexSignature:
    suffix = hashlib.sha256(operation.name.encode()).hexdigest()[:12]
    table_name = f"gateway_index_probe_{suffix}"
    index_name = f"gateway_index_probe_ix_{suffix}"
    quoted_table = _quoted_identifier(connection, table_name)
    quoted_source = _quoted_identifier(connection, operation.table)
    quoted_index = _quoted_identifier(connection, index_name)
    columns = ", ".join(
        _quoted_identifier(connection, column) for column in operation.columns
    )
    try:
        connection.exec_driver_sql(
            f"CREATE TEMP TABLE {quoted_table} (LIKE {quoted_source})"
        )
        connection.exec_driver_sql(
            f"CREATE INDEX {quoted_index} ON {quoted_table} ({columns}) "
            f"WHERE {operation.predicate}"
        )
        state = _index_state(
            connection,
            schema_name=str(
                connection.execute(
                    text(
                        "SELECT nspname FROM pg_namespace "
                        "WHERE oid = pg_my_temp_schema()"
                    )
                )
                .scalar_one()
            ),
            index_name=index_name,
        )
        if state is None:
            raise RuntimeError(
                f"failed to derive concurrent index signature: {operation.name}"
            )
        return state.signature
    finally:
        connection.exec_driver_sql(f"DROP TABLE IF EXISTS {quoted_table}")


def _create_index_sql(
    connection: Connection,
    operation: CreateIndexConcurrently,
) -> str:
    name = _quoted_identifier(connection, operation.name)
    table = _quoted_identifier(connection, operation.table)
    columns = ", ".join(
        _quoted_identifier(connection, column) for column in operation.columns
    )
    return (
        f"CREATE INDEX CONCURRENTLY {name} ON {table} ({columns}) "
        f"WHERE {operation.predicate}"
    )


def _apply_online_index_operation(
    connection: Connection,
    operation: CreateIndexConcurrently,
) -> OnlineIndexReceipt:
    schema_name = str(
        connection.execute(text("SELECT current_schema()")).scalar_one()
    )
    expected = _expected_index_signature(connection, operation)
    current = _index_state(
        connection,
        schema_name=schema_name,
        index_name=operation.name,
    )
    action: Literal["created", "reused", "rebuilt", "dropped", "absent"] = "created"
    if current is not None:
        if current.table != operation.table or current.signature != expected:
            raise RuntimeError(
                f"concurrent index definition drift detected: {operation.name}"
            )
        if current.valid and current.ready:
            return OnlineIndexReceipt(
                name=operation.name,
                action="reused",
                valid=True,
            )
        connection.exec_driver_sql(
            f"DROP INDEX CONCURRENTLY {_quoted_identifier(connection, operation.name)}"
        )
        action = "rebuilt"
    connection.exec_driver_sql(_create_index_sql(connection, operation))
    final = _index_state(
        connection,
        schema_name=schema_name,
        index_name=operation.name,
    )
    if (
        final is None
        or final.table != operation.table
        or final.signature != expected
        or not final.valid
        or not final.ready
    ):
        raise RuntimeError(
            f"concurrent index did not become valid: {operation.name}"
        )
    return OnlineIndexReceipt(
        name=operation.name,
        action=action,
        valid=True,
    )


def _apply_online_drop_index_operation(
    connection: Connection,
    operation: DropIndexConcurrently,
) -> OnlineIndexReceipt:
    schema_name = str(
        connection.execute(text("SELECT current_schema()")).scalar_one()
    )
    current = _index_state(
        connection,
        schema_name=schema_name,
        index_name=operation.name,
    )
    if current is None:
        return OnlineIndexReceipt(
            name=operation.name,
            action="absent",
            valid=True,
        )
    if current.table != operation.table:
        raise RuntimeError(
            f"concurrent index drop target drift detected: {operation.name} "
            f"belongs to {current.table}, expected {operation.table}"
        )
    connection.exec_driver_sql(
        f"DROP INDEX CONCURRENTLY {_quoted_identifier(connection, operation.name)}"
    )
    final = _index_state(
        connection,
        schema_name=schema_name,
        index_name=operation.name,
    )
    if final is not None:
        raise RuntimeError(
            f"concurrent index did not become absent: {operation.name}"
        )
    return OnlineIndexReceipt(
        name=operation.name,
        action="dropped",
        valid=True,
    )


def _run_online_index_operations(
    active_engine: Engine,
    operations: tuple[CreateIndexConcurrently | DropIndexConcurrently, ...],
) -> tuple[OnlineIndexReceipt, ...]:
    if not operations or active_engine.dialect.name != "postgresql":
        return ()
    settings = get_settings()
    timeout = max(1, settings.gateway_db_online_index_timeout_seconds)
    lock_timeout = max(1, settings.gateway_db_migration_lock_timeout_seconds)
    receipts: list[OnlineIndexReceipt] = []
    with active_engine.connect().execution_options(
        isolation_level="AUTOCOMMIT"
    ) as connection:
        connection.exec_driver_sql(f"SET lock_timeout TO '{lock_timeout}s'")
        connection.exec_driver_sql(f"SET statement_timeout TO '{timeout}s'")
        for operation in operations:
            if isinstance(operation, CreateIndexConcurrently):
                receipt = _apply_online_index_operation(connection, operation)
            elif isinstance(operation, DropIndexConcurrently):
                receipt = _apply_online_drop_index_operation(connection, operation)
            else:  # pragma: no cover - guarded by _online_operations_for_scripts
                raise TypeError(f"unsupported online operation: {type(operation)!r}")
            receipts.append(receipt)
    return tuple(receipts)


def _configure_postgresql_session(connection: Connection) -> int | None:
    if connection.dialect.name != "postgresql":
        return None
    settings = get_settings()
    lock_timeout = max(1, settings.gateway_db_migration_lock_timeout_seconds)
    statement_timeout = max(1, settings.gateway_db_migration_statement_timeout_seconds)
    lock_key = settings.gateway_db_migration_advisory_lock_key
    connection.exec_driver_sql(f"SET lock_timeout TO '{lock_timeout}s'")
    connection.exec_driver_sql(f"SET statement_timeout TO '{lock_timeout}s'")
    connection.execute(
        text("SELECT pg_advisory_lock(:lock_key)"),
        {"lock_key": lock_key},
    )
    connection.commit()
    connection.exec_driver_sql(f"SET statement_timeout TO '{statement_timeout}s'")
    connection.commit()
    return lock_key


def _release_postgresql_lock(
    connection: Connection, lock_key: int | None
) -> None:
    if lock_key is None:
        return
    if connection.in_transaction():
        connection.rollback()
    try:
        connection.execute(
            text("SELECT pg_advisory_unlock(:lock_key)"),
            {"lock_key": lock_key},
        )
        connection.commit()
    except SQLAlchemyError:
        connection.rollback()


def get_migration_status(
    target_engine: Engine | None = None,
) -> MigrationStatus:
    active_engine = target_engine if target_engine is not None else database.engine
    config = alembic_config(str(active_engine.url))
    head = migration_head(config)
    with active_engine.connect() as connection:
        revisions = _current_revisions(connection)
    return MigrationStatus(
        current_revisions=revisions,
        head_revision=head,
        at_head=revisions == (head,),
    )


def validate_schema_metadata(
    target_engine: Engine | None = None,
) -> None:
    active_engine = target_engine if target_engine is not None else database.engine
    with active_engine.connect() as connection:
        _validate_metadata_schema(connection)


def validate_database_schema(
    target_engine: Engine | None = None,
    *,
    allow_forward_revision: bool = False,
) -> MigrationStatus:
    active_engine = target_engine if target_engine is not None else database.engine
    status = get_migration_status(active_engine)
    forward_compatible = allow_forward_revision and revision_is_forward(
        status.current_revision,
        status.head_revision,
    )
    if not status.at_head and not forward_compatible:
        raise RuntimeError(
            "Database revision "
            f"{status.current_revision or 'unversioned'} does not match required "
            f"Alembic head {status.head_revision}"
        )
    validate_schema_metadata(active_engine)
    return status


def run_schema_migrations(
    target_engine: Engine | None = None,
) -> MigrationStatus:
    active_engine = target_engine if target_engine is not None else database.engine
    config = alembic_config(str(active_engine.url))
    head = migration_head(config)
    adopted = False
    scripts = ScriptDirectory.from_config(config)
    with active_engine.connect() as inspection_connection:
        initial_revisions = _current_revisions(inspection_connection)
        bootstrap_empty = _is_empty_database(inspection_connection)
    if len(initial_revisions) > 1:
        raise RuntimeError(
            f"Schema upgrade requires one database revision, found {initial_revisions}"
        )
    lower = initial_revisions[0] if initial_revisions else "base"
    pending_scripts = tuple(reversed(tuple(scripts.iterate_revisions(head, lower))))
    online_operations = _online_operations_for_scripts(pending_scripts)
    online_receipts: tuple[OnlineIndexReceipt, ...] = ()

    def upgrade_transactionally(connection: Connection) -> None:
        nonlocal adopted
        config.attributes["connection"] = connection
        config.attributes["gateway_online_index_bootstrap"] = bootstrap_empty
        try:
            with connection.begin():
                current = _current_revisions(connection)
                if not current and not _is_empty_database(connection):
                    _validate_legacy_identity(connection)
                    command.stamp(config, BASELINE_REVISION, purge=True)
                    adopted = True
                command.upgrade(config, "head")
                current = _current_revisions(connection)
                if current != (head,):
                    raise RuntimeError(
                        f"Database revision {current} did not reach Alembic head {head}"
                    )
                _validate_metadata_schema(connection)
        finally:
            config.attributes.pop("connection", None)
            config.attributes.pop("gateway_online_index_bootstrap", None)

    if active_engine.dialect.name == "postgresql":
        with active_engine.connect() as lock_connection:
            lock_key = _configure_postgresql_session(lock_connection)
            try:
                if not bootstrap_empty:
                    online_receipts = _run_online_index_operations(
                        active_engine,
                        online_operations,
                    )
                with active_engine.connect() as migration_connection:
                    upgrade_transactionally(migration_connection)
            finally:
                _release_postgresql_lock(lock_connection, lock_key)
    else:
        with active_engine.connect() as connection:
            upgrade_transactionally(connection)
    return MigrationStatus(
        current_revisions=(head,),
        head_revision=head,
        at_head=True,
        adopted_legacy_schema=adopted,
        online_index_operations=online_receipts,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gateway-schema-migrations")
    parser.add_argument(
        "operation",
        choices=(
            "check",
            "deployment-plan",
            "head",
            "status",
            "upgrade",
            "validate",
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.operation == "head":
        print(migration_head())
        return 0
    if args.operation == "check":
        print(json.dumps({"head_revision": migration_head()}, sort_keys=True))
        return 0
    if args.operation == "status":
        print(json.dumps(get_migration_status().to_dict(), sort_keys=True))
        return 0
    if args.operation == "deployment-plan":
        print(json.dumps(get_migration_plan().to_dict(), sort_keys=True))
        return 0
    if args.operation == "validate":
        print(json.dumps(validate_database_schema().to_dict(), sort_keys=True))
        return 0
    print(json.dumps(run_schema_migrations().to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
