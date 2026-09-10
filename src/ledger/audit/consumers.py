from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ledger.domain import utc_now
from ledger.errors import LedgerError, NotFoundError
from ledger.models import AuditConsumer, Checkpoint

# Conflict reasons surfaced in the ACKNOWLEDGEMENT_CONFLICT error envelope.
NOT_FIRST = "checkpoint_is_not_first"
SKIPPED = "checkpoint_is_not_successor"
REGRESSED = "checkpoint_precedes_current"
DUPLICATE = "checkpoint_already_acknowledged"


class AuditConsumerService:
    """Registration points for external audit systems and their checkpoint cursors."""

    def __init__(
        self,
        clock: Callable[[], datetime] = utc_now,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
    ) -> None:
        self.clock = clock
        self.uuid_factory = uuid_factory

    async def register_consumer(
        self,
        session: AsyncSession,
        *,
        consumer_name: str,
        idempotency_key: str,
    ) -> tuple[AuditConsumer, bool]:
        try:
            async with session.begin():
                existing = await session.scalar(
                    select(AuditConsumer).where(AuditConsumer.idempotency_key == idempotency_key)
                )
                if existing:
                    self._raise_unless_replay(existing, consumer_name)
                    return existing, False

                now = self.clock()
                consumer = AuditConsumer(
                    consumer_id=self.uuid_factory(),
                    consumer_name=consumer_name,
                    idempotency_key=idempotency_key,
                    created_at=now,
                    updated_at=now,
                )
                session.add(consumer)
                await session.flush()
                return consumer, True
        except IntegrityError:
            # Concurrent registrations racing on the unique idempotency key: settle from the row.
            await session.rollback()
            existing = await session.scalar(
                select(AuditConsumer).where(AuditConsumer.idempotency_key == idempotency_key)
            )
            if existing:
                self._raise_unless_replay(existing, consumer_name)
                return existing, False
            raise

    @staticmethod
    def _raise_unless_replay(existing: AuditConsumer, consumer_name: str) -> None:
        if existing.consumer_name == consumer_name:
            return
        raise LedgerError(
            "IDEMPOTENCY_CONFLICT",
            "idempotency key was already used with different parameters",
            409,
            {
                "idempotency_key": existing.idempotency_key,
                "consumer_id": str(existing.consumer_id),
                "consumer_name": existing.consumer_name,
            },
        )

    async def get_consumer(
        self, session: AsyncSession, consumer_id: uuid.UUID
    ) -> AuditConsumer:
        consumer = await session.scalar(
            select(AuditConsumer).where(AuditConsumer.consumer_id == consumer_id)
        )
        if not consumer:
            raise NotFoundError("audit_consumer", str(consumer_id))
        return consumer

    @staticmethod
    def _conflict(
        consumer: AuditConsumer,
        reason: str,
        current: Checkpoint | None,
        submitted: Checkpoint,
    ) -> LedgerError:
        return LedgerError(
            "ACKNOWLEDGEMENT_CONFLICT",
            "the checkpoint cannot follow the consumer's current acknowledgement point",
            409,
            {
                "reason": reason,
                "consumer_id": str(consumer.consumer_id),
                "submitted_checkpoint_id": str(submitted.checkpoint_id),
                "submitted_leaf_count": submitted.leaf_count,
                "current_checkpoint_id": (
                    str(current.checkpoint_id) if current is not None else None
                ),
                "current_leaf_count": current.leaf_count if current is not None else None,
                # The submitted checkpoint's previous_checkpoint_id must equal this value:
                # null for the very first acknowledgement, otherwise the current cursor.
                "expected_predecessor_checkpoint_id": (
                    str(current.checkpoint_id) if current is not None else None
                ),
            },
        )

    @classmethod
    def _classify(
        cls, current: Checkpoint | None, submitted: Checkpoint
    ) -> str | None:
        """Return the conflict reason, or None when the submitted checkpoint is the successor."""

        if current is None:
            return None if submitted.previous_checkpoint_id is None else NOT_FIRST
        if submitted.checkpoint_id == current.checkpoint_id:
            return DUPLICATE
        if submitted.leaf_count < current.leaf_count:
            return REGRESSED
        if submitted.previous_checkpoint_id != current.checkpoint_id:
            return SKIPPED
        return None

    async def acknowledge_checkpoint(
        self,
        session: AsyncSession,
        consumer_id: uuid.UUID,
        checkpoint_id: uuid.UUID,
    ) -> tuple[AuditConsumer, Checkpoint, bool]:
        """Advance the consumer cursor to ``checkpoint_id`` in one monotonic transaction.

        The conditional UPDATE compares the stored cursor with the expected predecessor, so
        concurrent acknowledgements serialize: exactly one transaction advances the cursor
        and the loser observes the committed cursor as a conflict without rolling it back.
        Returns ``(consumer, checkpoint, advanced)``.
        """

        async with session.begin():
            consumer = await session.scalar(
                select(AuditConsumer).where(AuditConsumer.consumer_id == consumer_id)
            )
            if not consumer:
                raise NotFoundError("audit_consumer", str(consumer_id))
            submitted = await session.get(Checkpoint, checkpoint_id)
            if not submitted:
                raise NotFoundError("checkpoint", str(checkpoint_id))

            current = (
                await session.get(Checkpoint, consumer.last_checkpoint_id)
                if consumer.last_checkpoint_id is not None
                else None
            )
            reason = self._classify(current, submitted)
            if reason is not None:
                raise self._conflict(consumer, reason, current, submitted)

            now = self.clock()
            result = await session.execute(
                update(AuditConsumer)
                .where(
                    AuditConsumer.id == consumer.id,
                    AuditConsumer.last_checkpoint_id.is_(
                        current.checkpoint_id if current is not None else None
                    ),
                )
                .values(
                    last_checkpoint_id=submitted.checkpoint_id,
                    last_acknowledged_at=now,
                    updated_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if result.rowcount == 0:
                # A concurrent acknowledgement committed first: classify against the new cursor.
                consumer = await session.scalar(
                    select(AuditConsumer)
                    .where(AuditConsumer.id == consumer.id)
                    .execution_options(populate_existing=True)
                )
                current = (
                    await session.get(Checkpoint, consumer.last_checkpoint_id)
                    if consumer.last_checkpoint_id is not None
                    else None
                )
                race_reason = self._classify(current, submitted) or SKIPPED
                raise self._conflict(consumer, race_reason, current, submitted)

            consumer = await session.scalar(
                select(AuditConsumer)
                .where(AuditConsumer.id == consumer.id)
                .execution_options(populate_existing=True)
            )
            return consumer, submitted, True

    async def current_checkpoint(
        self, session: AsyncSession, consumer: AuditConsumer
    ) -> Checkpoint | None:
        if consumer.last_checkpoint_id is None:
            return None
        return await session.get(Checkpoint, consumer.last_checkpoint_id)
