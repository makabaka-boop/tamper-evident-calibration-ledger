"""Create the append-only event and checkpoint ledgers.

Revision ID: 0001_append_only_ledger
Revises: None
"""

import sqlalchemy as sa
from alembic import op

revision = "0001_append_only_ledger"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("sequence", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(length=16), nullable=False),
        sa.Column("business_key", sa.String(length=128), nullable=False),
        sa.Column("content_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("instrument_id", sa.String(length=128), nullable=False),
        sa.Column("operator_id", sa.String(length=128), nullable=False),
        sa.Column("report_digest", sa.String(length=64), nullable=True),
        sa.Column("previous_event_id", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("leaf_hash", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "event_type IN ('report', 'revision', 'revocation')", name="ck_events_event_type"
        ),
        sa.CheckConstraint(
            "(event_type = 'revocation' AND report_digest IS NULL AND reason IS NOT NULL) OR "
            "(event_type IN ('report', 'revision') AND report_digest IS NOT NULL "
            "AND reason IS NULL)",
            name="ck_events_event_payload_shape",
        ),
        sa.ForeignKeyConstraint(["previous_event_id"], ["events.event_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("sequence"),
        sa.UniqueConstraint("business_key", name="uq_events_business_key"),
        sa.UniqueConstraint("event_id", name="uq_events_event_id"),
        sa.UniqueConstraint("previous_event_id", name="uq_events_previous_event_id"),
    )
    op.create_index("ix_events_event_id", "events", ["event_id"])
    op.create_index("ix_events_record_sequence", "events", ["record_id", "sequence"])

    op.create_table(
        "checkpoints",
        sa.Column("checkpoint_id", sa.Uuid(), nullable=False),
        sa.Column("leaf_count", sa.BigInteger(), nullable=False),
        sa.Column("last_event_sequence", sa.BigInteger(), nullable=False),
        sa.Column("root_hash", sa.String(length=64), nullable=False),
        sa.Column("previous_checkpoint_id", sa.Uuid(), nullable=True),
        sa.Column("previous_root_hash", sa.String(length=64), nullable=True),
        sa.Column("key_version", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signature", sa.String(length=64), nullable=False),
        sa.CheckConstraint("leaf_count > 0", name="ck_checkpoints_checkpoint_leaf_count_positive"),
        sa.ForeignKeyConstraint(
            ["previous_checkpoint_id"], ["checkpoints.checkpoint_id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("checkpoint_id"),
        sa.UniqueConstraint("leaf_count", name="uq_checkpoints_leaf_count"),
        sa.UniqueConstraint("last_event_sequence", name="uq_checkpoints_last_sequence"),
        sa.UniqueConstraint("previous_checkpoint_id", name="uq_checkpoints_previous_checkpoint_id"),
    )

    # Defense in depth: application roles can INSERT and SELECT, but history cannot be rewritten.
    op.execute(
        """
        CREATE FUNCTION ledger_reject_mutation() RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'append-only table % rejects %', TG_TABLE_NAME, TG_OP
            USING ERRCODE = 'integrity_constraint_violation';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER events_append_only
          BEFORE UPDATE OR DELETE ON events
          FOR EACH ROW EXECUTE FUNCTION ledger_reject_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER checkpoints_append_only
          BEFORE UPDATE OR DELETE ON checkpoints
          FOR EACH ROW EXECUTE FUNCTION ledger_reject_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS checkpoints_append_only ON checkpoints")
    op.execute("DROP TRIGGER IF EXISTS events_append_only ON events")
    op.drop_table("checkpoints")
    op.drop_index("ix_events_record_sequence", table_name="events")
    op.drop_index("ix_events_event_id", table_name="events")
    op.drop_table("events")
    op.execute("DROP FUNCTION IF EXISTS ledger_reject_mutation()")
