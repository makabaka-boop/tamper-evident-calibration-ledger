"""Audit access points: registered audit consumers with monotonic checkpoint cursors.

Revision ID: 0004_audit_consumers
Revises: 0003_audit_package_cancellation
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_audit_consumers"
down_revision = "0003_audit_package_cancellation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_consumers",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("consumer_id", sa.Uuid(), nullable=False),
        sa.Column("consumer_name", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("last_checkpoint_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["last_checkpoint_id"], ["checkpoints.checkpoint_id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("consumer_id", name="uq_audit_consumers_consumer_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_audit_consumers_idempotency_key"),
    )
    op.create_index("ix_audit_consumers_name", "audit_consumers", ["consumer_name"])

    # The registration identity is fixed for the life of the access point; only the
    # acknowledged checkpoint cursor and its timestamps may move forward.
    op.execute(
        """
        CREATE FUNCTION audit_consumer_reject_identity_mutation() RETURNS trigger AS $$
        BEGIN
          IF NEW.consumer_id IS DISTINCT FROM OLD.consumer_id
             OR NEW.consumer_name IS DISTINCT FROM OLD.consumer_name
             OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
             OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'audit consumer fixed identity rejects %', TG_OP
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_consumers_identity_immutable
          BEFORE UPDATE ON audit_consumers
          FOR EACH ROW EXECUTE FUNCTION audit_consumer_reject_identity_mutation()
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS audit_consumers_identity_immutable ON audit_consumers"
    )
    op.execute("DROP FUNCTION IF EXISTS audit_consumer_reject_identity_mutation()")
    op.drop_index("ix_audit_consumers_name", table_name="audit_consumers")
    op.drop_table("audit_consumers")
