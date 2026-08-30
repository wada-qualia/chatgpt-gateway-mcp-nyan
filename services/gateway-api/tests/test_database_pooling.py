from __future__ import annotations

from gateway_api import database
from gateway_api.config import Settings
from gateway_api.main import create_app
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError


def test_postgres_pool_engine_args_are_explicit_and_bounded() -> None:
    args = database._engine_args(
        "postgresql+psycopg://gateway@example/gateway",
        pool_size=5,
        max_overflow=10,
        pool_timeout=5.0,
        idle_in_transaction_timeout_seconds=300,
    )

    assert args == {
        "pool_size": 5,
        "max_overflow": 10,
        "pool_timeout": 5.0,
        "connect_args": {
            "options": "-c idle_in_transaction_session_timeout=300000"
        },
    }


def test_pool_defaults_keep_metrics_as_a_single_connection_bulkhead() -> None:
    settings = Settings()

    assert settings.gateway_db_pool_size == 5
    assert settings.gateway_db_max_overflow == 10
    assert settings.gateway_db_pool_timeout_seconds == 5.0
    assert settings.gateway_db_idle_in_transaction_timeout_seconds == 300
    assert settings.gateway_metrics_db_pool_size == 1
    assert settings.gateway_metrics_db_max_overflow == 0
    assert settings.gateway_metrics_db_pool_timeout_seconds == 1.0


def test_application_wires_metrics_pool_and_fail_fast_timeout_handler() -> None:
    app = create_app()

    assert app.state.metrics_cache.session_factory is database.MetricsSessionLocal
    assert SQLAlchemyTimeoutError in app.exception_handlers
