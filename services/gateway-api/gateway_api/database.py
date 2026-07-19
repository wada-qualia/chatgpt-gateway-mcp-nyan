from __future__ import annotations

from pathlib import Path
from typing import Iterator

from sqlalchemy import Connection, create_engine, inspect, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from .config import get_settings

Base = declarative_base()

# Stable project-specific key used only to serialize additive DDL between blue/green
# PostgreSQL replicas. The transaction-scoped lock is released automatically.
POSTGRES_SCHEMA_LOCK_KEY = 1129138007


def _engine_args(database_url: str) -> dict:
    if database_url.startswith("sqlite"):
        if database_url.startswith("sqlite:///"):
            db_path = database_url.replace("sqlite:///", "", 1)
            if db_path and db_path != ":memory:":
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        return {"connect_args": {"check_same_thread": False}}
    return {}


settings = get_settings()
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    **_engine_args(settings.database_url),
)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


FILE_CHANGE_ADDITIVE_COLUMNS = {
    "room_id": "VARCHAR(36)",
    "agent_id": "VARCHAR(36)",
    "lease_id": "VARCHAR(36)",
    "fencing_token": "INTEGER",
    "before_sha256": "VARCHAR(64)",
    "after_sha256": "VARCHAR(64)",
    "base_commit": "VARCHAR(128)",
    "branch_name": "VARCHAR(255)",
    "worktree_path": "TEXT",
}

FILE_CHANGE_ADDITIVE_INDEX_COLUMNS = (
    "room_id",
    "agent_id",
    "lease_id",
    "fencing_token",
)

WORK_ITEM_AUTONOMY_ADDITIVE_COLUMNS = {
    "required_capabilities": "JSON",
    "assignment_constraints": "JSON",
}


def _apply_additive_schema_upgrades(connection: Connection | None = None) -> None:
    if connection is None:
        with engine.begin() as owned_connection:
            _apply_additive_schema_upgrades(owned_connection)
        return
    inspector = inspect(connection)
    if "file_change_sets" not in inspector.get_table_names():
        return
    existing = {
        column["name"] for column in inspector.get_columns("file_change_sets")
    }
    for name, sql_type in FILE_CHANGE_ADDITIVE_COLUMNS.items():
        if name not in existing:
            connection.execute(
                text(f"ALTER TABLE file_change_sets ADD COLUMN {name} {sql_type}")
            )
    for name in FILE_CHANGE_ADDITIVE_INDEX_COLUMNS:
        connection.execute(
            text(
                f"CREATE INDEX IF NOT EXISTS ix_file_change_sets_{name} "
                f"ON file_change_sets ({name})"
            )
        )


def _apply_work_item_autonomy_upgrades(connection: Connection | None = None) -> None:
    if connection is None:
        with engine.begin() as owned_connection:
            _apply_work_item_autonomy_upgrades(owned_connection)
        return
    inspector = inspect(connection)
    if "agent_work_items" not in inspector.get_table_names():
        return
    existing = {
        column["name"] for column in inspector.get_columns("agent_work_items")
    }
    for name, sql_type in WORK_ITEM_AUTONOMY_ADDITIVE_COLUMNS.items():
        if name not in existing:
            connection.execute(
                text(f"ALTER TABLE agent_work_items ADD COLUMN {name} {sql_type}")
            )


def init_db() -> None:
    from . import models  # noqa: F401

    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:lock_key)"),
                {"lock_key": POSTGRES_SCHEMA_LOCK_KEY},
            )
        Base.metadata.create_all(bind=connection)
        _apply_additive_schema_upgrades(connection)
        _apply_work_item_autonomy_upgrades(connection)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
