from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative model registry for the ledger schema."""


SequenceType = BigInteger().with_variant(Integer, "sqlite")


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        CheckConstraint("event_type IN ('report', 'revision', 'revocation')", name="event_type"),
        CheckConstraint(
            "(event_type = 'revocation' AND report_digest IS NULL AND reason IS NOT NULL) OR "
            "(event_type IN ('report', 'revision') AND report_digest IS NOT NULL "
            "AND reason IS NULL)",
            name="event_payload_shape",
        ),
        UniqueConstraint("event_id", name="uq_events_event_id"),
        UniqueConstraint("business_key", name="uq_events_business_key"),
        UniqueConstraint("previous_event_id", name="uq_events_previous_event_id"),
        Index("ix_events_event_id", "event_id"),
        Index("ix_events_record_sequence", "record_id", "sequence"),
        Index("ix_events_instrument_sequence", "instrument_id", "sequence"),
    )

    sequence: Mapped[int] = mapped_column(SequenceType, primary_key=True, autoincrement=True)
    event_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    record_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    event_type: Mapped[str] = mapped_column(String(16), nullable=False)
    business_key: Mapped[str] = mapped_column(String(128), nullable=False)
    content_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    instrument_id: Mapped[str] = mapped_column(String(128), nullable=False)
    operator_id: Mapped[str] = mapped_column(String(128), nullable=False)
    report_digest: Mapped[str | None] = mapped_column(String(64))
    previous_event_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("events.event_id", ondelete="RESTRICT")
    )
    reason: Mapped[str | None] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    leaf_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class Checkpoint(Base):
    __tablename__ = "checkpoints"
    __table_args__ = (
        CheckConstraint("leaf_count > 0", name="checkpoint_leaf_count_positive"),
        UniqueConstraint("leaf_count", name="uq_checkpoints_leaf_count"),
        UniqueConstraint("last_event_sequence", name="uq_checkpoints_last_sequence"),
    )

    checkpoint_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    leaf_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_event_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    root_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_checkpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("checkpoints.checkpoint_id", ondelete="RESTRICT"), unique=True
    )
    previous_root_hash: Mapped[str | None] = mapped_column(String(64))
    key_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signature: Mapped[str] = mapped_column(String(64), nullable=False)


class AuditPackage(Base):
    """A trackable offline export of one instrument's events within a sealed boundary."""

    __tablename__ = "audit_packages"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'building', 'ready', 'failed', 'cancelling', 'cancelled')",
            name="audit_package_status",
        ),
        CheckConstraint(
            "request_fingerprint IS NOT NULL AND instrument_id IS NOT NULL "
            "AND checkpoint_id IS NOT NULL",
            name="audit_package_identity_present",
        ),
        CheckConstraint(
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
            name="audit_package_state_shape",
        ),
        CheckConstraint("attempt_count >= 0", name="audit_package_attempts_non_negative"),
        UniqueConstraint("package_id", name="uq_audit_packages_package_id"),
        UniqueConstraint("idempotency_key", name="uq_audit_packages_idempotency_key"),
        Index("ix_audit_packages_status_id", "status", "id"),
        Index("ix_audit_packages_instrument", "instrument_id"),
    )

    id: Mapped[int] = mapped_column(SequenceType, primary_key=True, autoincrement=True)
    package_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    instrument_id: Mapped[str] = mapped_column(String(128), nullable=False)
    checkpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("checkpoints.checkpoint_id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(64))
    failure_reason: Mapped[str | None] = mapped_column(Text)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    artifact_size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    event_count: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ready_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditPackageArtifact(Base):
    """Immutable ZIP bytes for a ready package, held in a separate row from the task."""

    __tablename__ = "audit_package_artifacts"
    __table_args__ = ()

    package_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("audit_packages.package_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    zip_content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
