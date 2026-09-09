from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ledger.canonical import canonical_json, digest_json, sha256_hex
from ledger.coordination import SEALER_ADVISORY_LOCK_ID
from ledger.domain import event_commitment_bytes, utc_now
from ledger.errors import LedgerError, NotFoundError
from ledger.merkle import leaf_hash
from ledger.models import Event
from ledger.schemas import SubmitReport, SubmitRevision, SubmitRevocation


class EventService:
    def __init__(
        self,
        clock: Callable[[], datetime] = utc_now,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
    ) -> None:
        self.clock = clock
        self.uuid_factory = uuid_factory

    @staticmethod
    def _fingerprint(payload: dict[str, Any]) -> str:
        return sha256_hex(canonical_json(payload))

    @staticmethod
    def _check_idempotency(existing: Event, fingerprint: str) -> Event:
        if existing.content_fingerprint != fingerprint:
            raise LedgerError(
                "IDEMPOTENCY_CONFLICT",
                "business key was already used with different content",
                409,
                {"business_key": existing.business_key, "event_id": str(existing.event_id)},
            )
        return existing

    async def _existing(self, session: AsyncSession, business_key: str) -> Event | None:
        return await session.scalar(select(Event).where(Event.business_key == business_key))

    @staticmethod
    async def _coordinate_insert(session: AsyncSession) -> None:
        """Keep sequence allocation outside an in-progress checkpoint boundary.

        Writers share this transaction lock with each other while the sealer takes it exclusively.
        Consequently the sealer cannot observe a later committed sequence while an earlier
        allocated sequence remains uncommitted.
        """

        dialect = session.bind.dialect.name if session.bind is not None else ""
        if dialect == "postgresql":
            await session.execute(
                text("SELECT pg_advisory_xact_lock_shared(:lock_id)"),
                {"lock_id": SEALER_ADVISORY_LOCK_ID},
            )

    def _new_event(
        self,
        *,
        event_type: Literal["report", "revision", "revocation"],
        business_key: str,
        fingerprint: str,
        instrument_id: str,
        operator_id: str,
        report_digest: str | None,
        previous_event_id: uuid.UUID | None,
        record_id: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> Event:
        event_id = self.uuid_factory()
        event = Event(
            event_id=event_id,
            record_id=record_id or event_id,
            event_type=event_type,
            business_key=business_key,
            content_fingerprint=fingerprint,
            instrument_id=instrument_id,
            operator_id=operator_id,
            report_digest=report_digest,
            previous_event_id=previous_event_id,
            reason=reason,
            occurred_at=self.clock(),
            leaf_hash="",
        )
        event.leaf_hash = leaf_hash(event_commitment_bytes(event)).hex()
        return event

    async def append_report(
        self, session: AsyncSession, request: SubmitReport
    ) -> tuple[Event, bool]:
        report_digest = digest_json(request.report)
        fingerprint = self._fingerprint(
            {
                "event_type": "report",
                "business_key": request.business_key,
                "instrument_id": request.instrument_id,
                "operator_id": request.operator_id,
                "report_digest": report_digest,
            }
        )
        try:
            async with session.begin():
                existing = await self._existing(session, request.business_key)
                if existing:
                    return self._check_idempotency(existing, fingerprint), False
                await self._coordinate_insert(session)
                event = self._new_event(
                    event_type="report",
                    business_key=request.business_key,
                    fingerprint=fingerprint,
                    instrument_id=request.instrument_id,
                    operator_id=request.operator_id,
                    report_digest=report_digest,
                    previous_event_id=None,
                )
                session.add(event)
                await session.flush()
                return event, True
        except IntegrityError:
            await session.rollback()
            existing = await self._existing(session, request.business_key)
            if existing:
                return self._check_idempotency(existing, fingerprint), False
            raise

    async def append_revision(
        self, session: AsyncSession, previous_event_id: uuid.UUID, request: SubmitRevision
    ) -> tuple[Event, bool]:
        report_digest = digest_json(request.report)
        fingerprint = self._fingerprint(
            {
                "event_type": "revision",
                "business_key": request.business_key,
                "previous_event_id": str(previous_event_id),
                "instrument_id": request.instrument_id,
                "operator_id": request.operator_id,
                "report_digest": report_digest,
            }
        )
        return await self._append_successor(
            session,
            previous_event_id=previous_event_id,
            event_type="revision",
            business_key=request.business_key,
            fingerprint=fingerprint,
            operator_id=request.operator_id,
            instrument_id=request.instrument_id,
            report_digest=report_digest,
            reason=None,
        )

    async def append_revocation(
        self, session: AsyncSession, previous_event_id: uuid.UUID, request: SubmitRevocation
    ) -> tuple[Event, bool]:
        fingerprint = self._fingerprint(
            {
                "event_type": "revocation",
                "business_key": request.business_key,
                "previous_event_id": str(previous_event_id),
                "operator_id": request.operator_id,
                "reason": request.reason,
            }
        )
        return await self._append_successor(
            session,
            previous_event_id=previous_event_id,
            event_type="revocation",
            business_key=request.business_key,
            fingerprint=fingerprint,
            operator_id=request.operator_id,
            instrument_id=None,
            report_digest=None,
            reason=request.reason,
        )

    async def _append_successor(
        self,
        session: AsyncSession,
        *,
        previous_event_id: uuid.UUID,
        event_type: Literal["revision", "revocation"],
        business_key: str,
        fingerprint: str,
        operator_id: str,
        instrument_id: str | None,
        report_digest: str | None,
        reason: str | None,
    ) -> tuple[Event, bool]:
        try:
            async with session.begin():
                existing = await self._existing(session, business_key)
                if existing:
                    return self._check_idempotency(existing, fingerprint), False

                await self._coordinate_insert(session)

                parent = await session.scalar(
                    select(Event).where(Event.event_id == previous_event_id).with_for_update()
                )
                if not parent:
                    raise NotFoundError("event", str(previous_event_id))
                if parent.event_type == "revocation":
                    raise LedgerError(
                        "RECORD_REVOKED",
                        "a revoked record cannot be revised or revoked again",
                        409,
                        {"event_id": str(previous_event_id)},
                    )
                successor = await session.scalar(
                    select(Event).where(Event.previous_event_id == previous_event_id)
                )
                if successor:
                    raise LedgerError(
                        "EVENT_ALREADY_SUPERSEDED",
                        "the selected event already has a successor",
                        409,
                        {
                            "event_id": str(previous_event_id),
                            "successor_event_id": str(successor.event_id),
                        },
                    )
                if instrument_id is not None and instrument_id != parent.instrument_id:
                    raise LedgerError(
                        "INSTRUMENT_MISMATCH",
                        "a revision cannot change the instrument identifier",
                        409,
                        {"expected": parent.instrument_id, "received": instrument_id},
                    )
                event = self._new_event(
                    event_type=event_type,
                    business_key=business_key,
                    fingerprint=fingerprint,
                    instrument_id=parent.instrument_id,
                    operator_id=operator_id,
                    report_digest=report_digest,
                    previous_event_id=parent.event_id,
                    record_id=parent.record_id,
                    reason=reason,
                )
                session.add(event)
                await session.flush()
                return event, True
        except IntegrityError:
            await session.rollback()
            existing = await self._existing(session, business_key)
            if existing:
                return self._check_idempotency(existing, fingerprint), False
            successor = await session.scalar(
                select(Event).where(Event.previous_event_id == previous_event_id)
            )
            if successor:
                raise LedgerError(
                    "EVENT_ALREADY_SUPERSEDED",
                    "the selected event already has a successor",
                    409,
                    {
                        "event_id": str(previous_event_id),
                        "successor_event_id": str(successor.event_id),
                    },
                ) from None
            raise
