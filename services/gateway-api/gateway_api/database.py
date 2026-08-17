from __future__ import annotations

from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from .config import get_settings

Base = declarative_base()


def _engine_args(
    database_url: str,
    *,
    pool_size: int | None = None,
    max_overflow: int | None = None,
    pool_timeout: float | None = None,
) -> dict:
    if database_url.startswith("sqlite"):
        if database_url.startswith("sqlite:///"):
            db_path = database_url.replace("sqlite:///", "", 1)
            if db_path and db_path != ":memory:":
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        return {"connect_args": {"check_same_thread": False}}
    args: dict[str, int | float] = {}
    if pool_size is not None:
        args["pool_size"] = pool_size
    if max_overflow is not None:
        args["max_overflow"] = max_overflow
    if pool_timeout is not None:
        args["pool_timeout"] = pool_timeout
    return args


settings = get_settings()
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    **_engine_args(
        settings.database_url,
        pool_size=settings.gateway_db_pool_size,
        max_overflow=settings.gateway_db_max_overflow,
        pool_timeout=settings.gateway_db_pool_timeout_seconds,
    ),
)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)

if settings.database_url.startswith("sqlite"):
    # Tests and local SQLite deployments must retain one engine/session factory.
    # PostgreSQL production gets a separate metrics pool below.
    metrics_engine = engine
    MetricsSessionLocal = SessionLocal
else:
    metrics_engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        **_engine_args(
            settings.database_url,
            pool_size=settings.gateway_metrics_db_pool_size,
            max_overflow=settings.gateway_metrics_db_max_overflow,
            pool_timeout=settings.gateway_metrics_db_pool_timeout_seconds,
        ),
    )
    MetricsSessionLocal = sessionmaker(
        bind=metrics_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )


def init_db():
    from .schema_migrations import run_schema_migrations

    return run_schema_migrations()


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
