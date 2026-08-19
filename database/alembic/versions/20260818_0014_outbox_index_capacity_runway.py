from __future__ import annotations

from alembic import op
from gateway_api.migration_operations import drop_index_concurrently
from sqlalchemy import inspect

revision = "20260818_0014"
down_revision = "20260818_0013"
deployment_compatibility = "expand"
branch_labels = None
depends_on = None

_TABLE = "outbox_events"
_DROP_INDEX_NAMES = (
    "ix_outbox_events_audit_event_id",
    "ix_outbox_events_published_at",
    "ix_outbox_events_lock_token",
    "ix_outbox_events_locked_by",
    "ix_outbox_events_subject",
    "ix_outbox_events_replayed_from_id",
)
online_operations = tuple(
    drop_index_concurrently(name=name, table=_TABLE) for name in _DROP_INDEX_NAMES
)


def _existing_indexes() -> set[str]:
    return {item["name"] for item in inspect(op.get_bind()).get_indexes(_TABLE)}


def _verify_schema() -> None:
    remaining = sorted(_existing_indexes().intersection(_DROP_INDEX_NAMES))
    if remaining:
        raise RuntimeError(
            "Gateway outbox capacity indexes were not removed: " + ", ".join(remaining)
        )
    unique_constraints = {
        item["name"]
        for item in inspect(op.get_bind()).get_unique_constraints(_TABLE)
        if item.get("name")
    }
    if "uq_outbox_event_audit_event" not in unique_constraints:
        raise RuntimeError(
            "Gateway outbox audit-event uniqueness constraint is missing"
        )


def upgrade() -> None:
    bootstrap = bool(
        op.get_context().config.attributes.get("gateway_online_index_bootstrap")
    )
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and not bootstrap:
        _verify_schema()
        return

    existing = _existing_indexes()
    for index_name in _DROP_INDEX_NAMES:
        if index_name in existing:
            op.drop_index(index_name, table_name=_TABLE)
    _verify_schema()


def downgrade() -> None:
    raise RuntimeError("Gateway outbox index capacity migration is irreversible")
