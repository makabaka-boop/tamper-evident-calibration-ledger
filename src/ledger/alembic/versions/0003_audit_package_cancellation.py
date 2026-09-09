"""Audit package cancellation: cancelling/cancelled states and cancel timestamps.

Revision ID: 0003_audit_package_cancellation
Revises: 0002_audit_packages
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_audit_package_cancellation"
down_revision = "0002_audit_packages"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_packages",
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "audit_packages",
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.drop_constraint("ck_audit_packages_audit_package_status", "audit_packages", type_="check")
    op.create_check_constraint(
        "ck_audit_packages_audit_package_status",
        "audit_packages",
        "status IN ('pending', 'building', 'ready', 'failed', 'cancelling', 'cancelled')",
    )
    op.drop_constraint(
        "ck_audit_packages_audit_package_state_shape", "audit_packages", type_="check"
    )
    op.create_check_constraint(
        "ck_audit_packages_audit_package_state_shape",
        "audit_packages",
        "(status = 'ready' AND ready_at IS NOT NULL AND failure_code IS NULL "
        "AND failure_reason IS NULL AND artifact_sha256 IS NOT NULL "
        "AND artifact_size_bytes IS NOT NULL AND event_count IS NOT NULL "
        "AND lease_owner IS NULL AND lease_expires_at IS NULL "
        "AND cancel_requested_at IS NULL AND cancelled_at IS NULL) OR "
        "(status = 'failed' AND failed_at IS NOT NULL AND failure_reason IS NOT NULL) OR "
        "(status = 'pending' AND lease_owner IS NULL AND lease_expires_at IS NULL "
        "AND ready_at IS NULL AND failed_at IS NULL "
        "AND failure_code IS NULL AND failure_reason IS NULL) OR "
        "(status = 'building' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL "
        "AND ready_at IS NULL AND failed_at IS NULL "
        "AND failure_code IS NULL AND failure_reason IS NULL "
        "AND cancel_requested_at IS NULL AND cancelled_at IS NULL) OR "
        "(status = 'cancelling' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL "
        "AND ready_at IS NULL AND failed_at IS NULL "
        "AND failure_code IS NULL AND failure_reason IS NULL "
        "AND cancel_requested_at IS NOT NULL AND cancelled_at IS NULL) OR "
        "(status = 'cancelled' AND lease_owner IS NULL AND lease_expires_at IS NULL "
        "AND ready_at IS NULL AND failed_at IS NULL "
        "AND failure_code IS NULL AND failure_reason IS NULL "
        "AND artifact_sha256 IS NULL AND artifact_size_bytes IS NULL "
        "AND event_count IS NULL AND cancel_requested_at IS NOT NULL "
        "AND cancelled_at IS NOT NULL)",
    )


def downgrade() -> None:
    # Cancellation states never carry an artifact; no artifact rows can exist for them.
    op.execute("DELETE FROM audit_packages WHERE status IN ('cancelling', 'cancelled')")
    op.drop_constraint(
        "ck_audit_packages_audit_package_state_shape", "audit_packages", type_="check"
    )
    op.create_check_constraint(
        "ck_audit_packages_audit_package_state_shape",
        "audit_packages",
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
    )
    op.drop_constraint("ck_audit_packages_audit_package_status", "audit_packages", type_="check")
    op.create_check_constraint(
        "ck_audit_packages_audit_package_status",
        "audit_packages",
        "status IN ('pending', 'building', 'ready', 'failed')",
    )
    op.drop_column("audit_packages", "cancelled_at")
    op.drop_column("audit_packages", "cancel_requested_at")
