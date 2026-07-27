from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, text

revision = "20260727_0010"
down_revision = "20260726_0009"
branch_labels = None
depends_on = None


def _verify_schema() -> None:
    connection = op.get_bind()
    inspector = inspect(connection)
    tables = set(inspector.get_table_names())
    required = {"mcp_catalog_index_generations", "mcp_catalog_embeddings"}
    missing = required - tables
    if missing:
        raise RuntimeError(f"Hybrid retrieval migration missing tables: {sorted(missing)}")
    generation_columns = {
        column["name"] for column in inspector.get_columns("mcp_catalog_index_generations")
    }
    embedding_columns = {
        column["name"] for column in inspector.get_columns("mcp_catalog_embeddings")
    }
    if {
        "owner_subject",
        "scope_server_id",
        "model_key",
        "model_version",
        "dimensions",
        "generation",
        "status",
        "source_catalog_sha256",
        "document_count",
        "supersedes_generation_id",
        "version",
    } - generation_columns:
        raise RuntimeError("Hybrid retrieval generation schema is incomplete")
    if {
        "owner_subject",
        "generation_id",
        "revision_id",
        "schema_hash",
        "document_sha256",
        "dimensions",
        "vector",
    } - embedding_columns:
        raise RuntimeError("Hybrid retrieval embedding schema is incomplete")
    generation_indexes = {
        item["name"]
        for item in inspector.get_indexes("mcp_catalog_index_generations")
    }
    required_generation_indexes = {
        "ix_mcp_catalog_index_generation_owner_status",
        "ix_mcp_catalog_index_generation_model",
        "uq_mcp_catalog_index_generation_global",
        "uq_mcp_catalog_index_generation_active_owner",
    }
    if required_generation_indexes - generation_indexes:
        raise RuntimeError("Hybrid retrieval generation indexes are incomplete")
    embedding_indexes = {
        item["name"] for item in inspector.get_indexes("mcp_catalog_embeddings")
    }
    required_embedding_indexes = {
        "ix_mcp_catalog_embedding_owner_generation",
        "ix_mcp_catalog_embedding_owner_revision",
    }
    if required_embedding_indexes - embedding_indexes:
        raise RuntimeError("Hybrid retrieval embedding indexes are incomplete")


def _upgrade_portable() -> None:
    active_where = text("status = 'active'")
    global_where = text("scope_server_id IS NULL")
    op.create_table(
        "mcp_catalog_index_generations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("owner_subject", sa.String(length=255), nullable=False),
        sa.Column("scope_server_id", sa.String(length=36), nullable=True),
        sa.Column("model_key", sa.String(length=120), nullable=False),
        sa.Column("model_version", sa.String(length=120), nullable=False),
        sa.Column("dimensions", sa.Integer(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="building"),
        sa.Column("source_catalog_sha256", sa.String(length=64), nullable=False),
        sa.Column("document_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("supersedes_generation_id", sa.String(length=36), nullable=True),
        sa.Column("created_by_subject", sa.String(length=255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scope_server_id"], ["mcp_servers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["supersedes_generation_id"],
            ["mcp_catalog_index_generations.id"],
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "owner_subject",
            "scope_server_id",
            "model_key",
            "model_version",
            "generation",
            name="uq_mcp_catalog_index_generation_model_generation",
        ),
        sa.CheckConstraint(
            "status in ('building', 'ready', 'active', 'retired', 'failed')",
            name="ck_mcp_catalog_index_generation_status",
        ),
        sa.CheckConstraint(
            "dimensions between 1 and 4096",
            name="ck_mcp_catalog_index_generation_dimensions",
        ),
        sa.CheckConstraint(
            "generation > 0", name="ck_mcp_catalog_index_generation_generation"
        ),
        sa.CheckConstraint(
            "document_count >= 0",
            name="ck_mcp_catalog_index_generation_document_count",
        ),
        sa.CheckConstraint("version > 0", name="ck_mcp_catalog_index_generation_version"),
    )
    op.create_index(
        "ix_mcp_catalog_index_generation_owner_status",
        "mcp_catalog_index_generations",
        ["owner_subject", "status"],
    )
    op.create_index(
        "ix_mcp_catalog_index_generation_model",
        "mcp_catalog_index_generations",
        ["owner_subject", "model_key", "model_version"],
    )
    for name, columns in (
        ("ix_mcp_catalog_index_generations_owner_subject", ["owner_subject"]),
        ("ix_mcp_catalog_index_generations_scope_server_id", ["scope_server_id"]),
        ("ix_mcp_catalog_index_generations_status", ["status"]),
        (
            "ix_mcp_catalog_index_generations_supersedes_generation_id",
            ["supersedes_generation_id"],
        ),
    ):
        op.create_index(name, "mcp_catalog_index_generations", columns)
    op.create_index(
        "uq_mcp_catalog_index_generation_global",
        "mcp_catalog_index_generations",
        ["owner_subject", "model_key", "model_version", "generation"],
        unique=True,
        sqlite_where=global_where,
        postgresql_where=global_where,
    )
    op.create_index(
        "uq_mcp_catalog_index_generation_active_owner",
        "mcp_catalog_index_generations",
        ["owner_subject"],
        unique=True,
        sqlite_where=active_where,
        postgresql_where=active_where,
    )
    op.create_table(
        "mcp_catalog_embeddings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("owner_subject", sa.String(length=255), nullable=False),
        sa.Column("generation_id", sa.String(length=36), nullable=False),
        sa.Column("revision_id", sa.String(length=36), nullable=False),
        sa.Column("schema_hash", sa.String(length=64), nullable=False),
        sa.Column("document_sha256", sa.String(length=64), nullable=False),
        sa.Column("dimensions", sa.Integer(), nullable=False),
        sa.Column("vector", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["generation_id"], ["mcp_catalog_index_generations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["revision_id"], ["mcp_tool_revisions.id"], ondelete="CASCADE"
        ),
        sa.UniqueConstraint(
            "generation_id",
            "revision_id",
            name="uq_mcp_catalog_embedding_generation_revision",
        ),
        sa.CheckConstraint(
            "dimensions between 1 and 4096",
            name="ck_mcp_catalog_embedding_dimensions",
        ),
    )
    for name, columns in (
        ("ix_mcp_catalog_embedding_owner_generation", ["owner_subject", "generation_id"]),
        ("ix_mcp_catalog_embedding_owner_revision", ["owner_subject", "revision_id"]),
        ("ix_mcp_catalog_embeddings_owner_subject", ["owner_subject"]),
        ("ix_mcp_catalog_embeddings_generation_id", ["generation_id"]),
        ("ix_mcp_catalog_embeddings_revision_id", ["revision_id"]),
    ):
        op.create_index(name, "mcp_catalog_embeddings", columns)


def upgrade() -> None:
    connection = op.get_bind()
    required = {"mcp_catalog_index_generations", "mcp_catalog_embeddings"}
    existing = required.intersection(inspect(connection).get_table_names())
    if existing and existing != required:
        raise RuntimeError(
            f"partial hybrid retrieval schema: {sorted(existing)}"
        )
    if not existing:
        if connection.dialect.name == "postgresql":
            root = __import__("pathlib").Path(__file__).resolve().parents[2]
            op.execute(
                (
                    root
                    / "migrations"
                    / "011_mcp_catalog_hybrid_retrieval.sql"
                ).read_text()
            )
        else:
            _upgrade_portable()
    _verify_schema()


def downgrade() -> None:
    raise RuntimeError("Downgrade is intentionally unsupported for hybrid retrieval storage")
