from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Iterator

import pytest
from gateway_api.models import AuditEvent, Device, SecretBlob, User
from gateway_api.routers.devices import delete_device
from gateway_api.schema_migrations import run_schema_migrations
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

POSTGRES_URL = os.getenv('GATEWAY_TEST_POSTGRES_URL')
pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason='GATEWAY_TEST_POSTGRES_URL is required for PostgreSQL device-delete tests',
)


@pytest.fixture
def pg_engine() -> Iterator[Engine]:
    assert POSTGRES_URL is not None
    base_url = make_url(POSTGRES_URL)
    database_name = f'gateway_device_delete_{uuid.uuid4().hex}'
    admin_engine = create_engine(
        base_url.set(database='postgres'),
        isolation_level='AUTOCOMMIT',
    )
    quoted_name = admin_engine.dialect.identifier_preparer.quote(database_name)
    with admin_engine.connect() as connection:
        connection.exec_driver_sql(f'CREATE DATABASE {quoted_name}')
    target_engine = create_engine(base_url.set(database=database_name))
    try:
        run_schema_migrations(target_engine)
        yield target_engine
    finally:
        target_engine.dispose()
        with admin_engine.connect() as connection:
            connection.execute(
                text(
                    'SELECT pg_terminate_backend(pid) FROM pg_stat_activity '
                    'WHERE datname = :database_name AND pid <> pg_backend_pid()'
                ),
                {'database_name': database_name},
            )
            connection.exec_driver_sql(f'DROP DATABASE {quoted_name}')
        admin_engine.dispose()


def test_postgresql_device_delete_removes_device_before_credential_secret(
    pg_engine: Engine,
) -> None:
    session_factory = sessionmaker(bind=pg_engine, expire_on_commit=False)
    owner_subject = 'test:device-delete'
    device_id = str(uuid.uuid4())
    secret_id = str(uuid.uuid4())

    with session_factory() as session:
        user = User(
            subject=owner_subject,
            username='device-delete-test',
            roles=['gateway-user'],
            provider='test',
        )
        session.add(user)
        session.add(
            SecretBlob(
                id=secret_id,
                owner_subject=owner_subject,
                kind='ssh:password',
                ciphertext='encrypted-test-value',
            )
        )
        session.flush()
        session.add(
            Device(
                id=device_id,
                owner_subject=owner_subject,
                name='postgres-delete-test',
                kind='ssh',
                host='127.0.0.1',
                port=22,
                username='robot',
                auth_type='password',
                credential_secret_id=secret_id,
                status='registered',
                meta={},
            )
        )
        session.commit()

        result = asyncio.run(delete_device(device_id, user=user, db=session))

        assert result == {'ok': True}
        assert session.get(Device, device_id) is None
        assert session.get(SecretBlob, secret_id) is None
        audit = (
            session.query(AuditEvent)
            .filter(
                AuditEvent.event_type == 'gateway.device.deleted.v1',
                AuditEvent.resource_id == device_id,
            )
            .one()
        )
        assert audit.actor_subject == owner_subject
