from __future__ import annotations

import argparse
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError

from . import database
from . import models as _models
from .config import get_settings

BASELINE_REVISION = "20260725_0001"
PROJECTION_REVISION = "20260725_0002"
HEAD_REVISION = "20260727_0011"
LEGACY_ANCHOR_TABLES = {"users", "secret_blobs", "oauth_clients"}
REVISION_PATTERN = re.compile(r"^(?P<date>\d{8})_(?P<sequence>\d{4})$")


@dataclass(frozen=True)
class MigrationPlan:
    current_revision: str | None
    head_revision: str
    pending_revisions: tuple[str, ...]
    compatibility: tuple[str, ...]
    safe_for_live_expand: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class MigrationStatus:
    current_revisions: tuple[str, ...]
    head_revision: str
    at_head: bool
    adopted_legacy_schema: bool = False

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
    return MigrationPlan(
        current_revision=current,
        head_revision=head,
        pending_revisions=pending,
        compatibility=compatibility,
        safe_for_live_expand=all(value == "expand" for value in compatibility),
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


def _configure_postgresql_session(connection: Connection) -> int | None:
    if connection.dialect.name != "postgresql":
        return None
    settings = get_settings()
    lock_timeout = max(1, settings.gateway_db_migration_lock_timeout_seconds)
    statement_timeout = max(
        lock_timeout, settings.gateway_db_migration_statement_timeout_seconds
    )
    lock_key = settings.gateway_db_migration_advisory_lock_key
    connection.exec_driver_sql(f"SET lock_timeout TO '{lock_timeout}s'")
    connection.exec_driver_sql(f"SET statement_timeout TO '{statement_timeout}s'")
    connection.execute(
        text("SELECT pg_advisory_lock(:lock_key)"),
        {"lock_key": lock_key},
    )
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
    with active_engine.connect() as connection:
        lock_key = _configure_postgresql_session(connection)
        try:
            config.attributes["connection"] = connection
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
            _release_postgresql_lock(connection, lock_key)
    return MigrationStatus(
        current_revisions=(head,),
        head_revision=head,
        at_head=True,
        adopted_legacy_schema=adopted,
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
