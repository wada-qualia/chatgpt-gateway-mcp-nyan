from __future__ import annotations

from alembic import op

revision = "20260726_0005"
down_revision = "20260725_0004"
branch_labels = None
depends_on = None

_CONSTRAINT_NAME = "uq_mcp_runtime_connection_instance"
_LEGACY_DEFINITION = "UNIQUE (owner_subject, connection_instance_id)"
_EXPECTED_DEFINITION = (
    "UNIQUE (owner_subject, server_id, connection_instance_id)"
)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return

    duplicate = connection.exec_driver_sql(
        """
        SELECT 1
        FROM mcp_runtime_connections
        GROUP BY owner_subject, server_id, connection_instance_id
        HAVING COUNT(*) > 1
        LIMIT 1
        """
    ).scalar_one_or_none()
    if duplicate is not None:
        raise RuntimeError(
            "mcp_runtime_connections contains duplicate target identities"
        )

    current_definition = connection.exec_driver_sql(
        """
        SELECT pg_get_constraintdef(oid)
        FROM pg_constraint
        WHERE conrelid = 'mcp_runtime_connections'::regclass
          AND conname = %s
          AND contype = 'u'
        """,
        (_CONSTRAINT_NAME,),
    ).scalar_one_or_none()
    if current_definition == _EXPECTED_DEFINITION:
        return
    if current_definition != _LEGACY_DEFINITION:
        raise RuntimeError(
            "unexpected mcp_runtime_connections connection identity constraint: "
            f"{current_definition!r}"
        )

    op.drop_constraint(
        _CONSTRAINT_NAME,
        "mcp_runtime_connections",
        type_="unique",
    )
    op.create_unique_constraint(
        _CONSTRAINT_NAME,
        "mcp_runtime_connections",
        ["owner_subject", "server_id", "connection_instance_id"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "multi-server MCP runtime connection cardinality downgrade is not supported"
    )
