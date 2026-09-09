"""Instrument audit packages: task queue and artifact tables.

Revision ID: 0002_audit_packages
Revises: 0001_append_only_ledger
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_audit_packages"
down_revision = "0001_append_only_ledger"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_packages",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("package_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("instrument_id", sa.String(length=128), nullable=False),
        sa.Column("checkpoint_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=True),
        sa.Column("artifact_size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("event_count", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ready_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'building', 'ready', 'failed')",
            name="ck_audit_packages_audit_package_status",
        ),
        sa.CheckConstraint(
            "request_fingerprint IS NOT NULL AND instrument_id IS NOT NULL "
            "AND checkpoint_id IS NOT NULL",
            name="ck_audit_packages_audit_package_identity_present",
        ),
        sa.CheckConstraint(
            "(status = 'ready' AND ready_at IS NOT NULL AND failure_code IS NULL "
            "AND failure_reason IS NULL AND artifact_sha256 IS NOT NULL "
            "AND artifact_size_bytes IS NOT NULL AND event_count IS NOT NULL "
            "AND lease_owner IS NULL AND lease_expires_at IS NULL) OR "
            "(status = 'failed' AND failed_at IS NOT NULL AND failure_reason IS NOT NULL) OR "
            "(status = 'pending' AND lease_owner IS NULL AND lease_expires_at IS NULL "
            "AND ready_at IS NULL AND failed_at IS NULL "
            "AND failure_code IS NULL AND failure_reason IS NULL) OR "
            "(status = 'building' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND ready_at IS NULL AND failed_at IS NULL "
            "AND failure_code IS NULL AND failure_reason IS NULL)",
            name="ck_audit_packages_audit_package_state_shape",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0", name="ck_audit_packages_audit_package_attempts_non_negative"
        ),
        sa.ForeignKeyConstraint(
            ["checkpoint_id"], ["checkpoints.checkpoint_id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("package_id", name="uq_audit_packages_package_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_audit_packages_idempotency_key"),
    )
    op.create_index(
        "ix_audit_packages_status_id", "audit_packages", ["status", "id"]
    )
    op.create_index("ix_audit_packages_instrument", "audit_packages", ["instrument_id"])

    op.create_table(
        "audit_package_artifacts",
        sa.Column("package_id", sa.Uuid(), nullable=False),
        sa.Column("zip_content", sa.LargeBinary(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["package_id"], ["audit_packages.package_id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("package_id"),
    )

    # Boundary-collection path: events of one instrument in database sequence order.
    op.create_index(
        "ix_events_instrument_sequence", "events", ["instrument_id", "sequence"]
    )

    # Defense in depth: task lifecycle may transition, but a fixed package identity and
    # its produced artifact can never be rewritten.
    op.execute(
        """
        CREATE FUNCTION audit_package_reject_identity_mutation() RETURNS trigger AS $$
        BEGIN
          IF NEW.package_id IS DISTINCT FROM OLD.package_id
             OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
             OR NEW.request_fingerprint IS DISTINCT FROM OLD.request_fingerprint
             OR NEW.instrument_id IS DISTINCT FROM OLD.instrument_id
             OR NEW.checkpoint_id IS DISTINCT FROM OLD.checkpoint_id
             OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'audit package fixed identity rejects %', TG_OP
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_packages_identity_immutable
          BEFORE UPDATE ON audit_packages
          FOR EACH ROW EXECUTE FUNCTION audit_package_reject_identity_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_package_artifacts_append_only
          BEFORE UPDATE OR DELETE ON audit_package_artifacts
          FOR EACH ROW EXECUTE FUNCTION ledger_reject_mutation()
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS audit_package_artifacts_append_only "
        "ON audit_package_artifacts"
    )
    op.execute("DROP TRIGGER IF EXISTS audit_packages_identity_immutable ON audit_packages")
    op.execute("DROP FUNCTION IF EXISTS audit_package_reject_identity_mutation()")
    op.drop_index("ix_events_instrument_sequence", table_name="events")
    op.drop_table("audit_package_artifacts")
    op.drop_index("ix_audit_packages_instrument", table_name="audit_packages")
    op.drop_index("ix_audit_packages_status_id", table_name="audit_packages")
    op.drop_table("audit_packages")
