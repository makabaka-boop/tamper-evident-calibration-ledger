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
