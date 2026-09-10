from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
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

# Bound the re-check loop when concurrent writers win a business-key race.
_BATCH_INSERT_ATTEMPTS = 4


@dataclass(frozen=True)
class _PreparedReport:
    request: SubmitReport
    report_digest: str
    fingerprint: str


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

    @classmethod
    def _invalid_report(cls, index: int, request: SubmitReport, exc: Exception) -> LedgerError:
        return LedgerError(
            "BATCH_ITEM_INVALID",
            "a report in the batch failed the single-report validation rules",
            422,
            {
                "index": index,
                "business_key": request.business_key,
                "reason": "invalid_report",
                "message": str(exc),
            },
        )

    def _prepare_report(self, index: int, request: SubmitReport) -> _PreparedReport:
        try:
            report_digest = digest_json(request.report)
        except ValueError as exc:
            raise self._invalid_report(index, request, exc) from exc
        fingerprint = self._fingerprint(
            {
                "event_type": "report",
                "business_key": request.business_key,
                "instrument_id": request.instrument_id,
                "operator_id": request.operator_id,
                "report_digest": report_digest,
            }
        )
        return _PreparedReport(request, report_digest, fingerprint)

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
        prepared = self._prepare_report(0, request)
        try:
            async with session.begin():
                existing = await self._existing(session, request.business_key)
                if existing:
                    return self._check_idempotency(existing, prepared.fingerprint), False
                await self._coordinate_insert(session)
                event = self._new_report_event(prepared)
                session.add(event)
                await session.flush()
                return event, True
        except IntegrityError:
            await session.rollback()
            existing = await self._existing(session, request.business_key)
            if existing:
                return self._check_idempotency(existing, prepared.fingerprint), False
            raise

    async def append_report_batch(
        self, session: AsyncSession, requests: list[SubmitReport]
    ) -> list[tuple[Event, bool]]:
        """Append one to fifty reports atomically, returning results in input order.

        Reports repeat the single endpoint's validation and idempotency rules. A business key
        appearing several times in the batch with identical committed content folds onto one
        event (the first occurrence is reported as created, later ones as not); a key reused
        with different content, inside the batch or against a committed event, aborts the whole
        batch and names the first offending item index.
        """

        prepared = [
            self._prepare_report(index, request) for index, request in enumerate(requests)
        ]

        # Detect intra-batch collisions before opening the transaction so a conflict proves
        # zero writes, and validation errors still name the earliest failing item.
        first_index: dict[str, int] = {}
        for index, item in enumerate(prepared):
            prior = first_index.get(item.request.business_key)
            if prior is None:
                first_index[item.request.business_key] = index
            elif prepared[prior].fingerprint != item.fingerprint:
                raise LedgerError(
                    "IDEMPOTENCY_CONFLICT",
                    "business key was already used in this batch with different content",
                    409,
                    {
                        "index": index,
                        "first_index": prior,
                        "business_key": item.request.business_key,
                    },
                )

        attempt = 0
        while True:
            attempt += 1
            try:
                async with session.begin():
                    return await self._insert_report_batch(session, prepared)
            except IntegrityError as exc:
                await session.rollback()
                # A concurrent single or batch writer may have committed one of the keys while
                # this transaction waited on the sequence/uniqueness constraint. Re-read: if
                # every raced key now matches its promised content, the re-attempt collapses
                # onto those events; otherwise the conflict surfaces with its item index.
                conflict = await self._committed_batch_conflict(session, prepared)
                if conflict is not None:
                    raise conflict from None
                if attempt >= _BATCH_INSERT_ATTEMPTS:
                    raise exc

    @staticmethod
    async def _committed_batch_conflict(
        session: AsyncSession, prepared: list[_PreparedReport]
    ) -> LedgerError | None:
        # Re-read inside an explicit transaction so the session is clean for a begin() retry
        # when every raced key has merely been committed with identical content elsewhere.
        async with session.begin():
            keys = list({item.request.business_key for item in prepared})
            existing_rows = list(
                (
                    await session.scalars(select(Event).where(Event.business_key.in_(keys)))
                ).all()
            )
            existing = {event.business_key: event for event in existing_rows}
            for index, item in enumerate(prepared):
                row = existing.get(item.request.business_key)
                if row is not None and row.content_fingerprint != item.fingerprint:
                    return LedgerError(
                        "IDEMPOTENCY_CONFLICT",
                        "business key was already used with different content",
                        409,
                        {
                            "index": index,
                            "business_key": item.request.business_key,
                            "event_id": str(row.event_id),
                        },
                    )
        return None

    async def _insert_report_batch(
        self, session: AsyncSession, prepared: list[_PreparedReport]
    ) -> list[tuple[Event, bool]]:
        await self._coordinate_insert(session)

        keys = [item.request.business_key for item in prepared]
        existing_rows = list(
            (
                await session.scalars(select(Event).where(Event.business_key.in_(keys)))
            ).all()
        )
        resolved: dict[str, Event] = {event.business_key: event for event in existing_rows}

        results: list[tuple[Event, bool]] = []
        appended: dict[str, Event] = {}
        for index, item in enumerate(prepared):
            key = item.request.business_key
            existing = resolved.get(key)
            if existing is not None:
                try:
                    event = self._check_idempotency(existing, item.fingerprint)
                except LedgerError as exc:
                    exc.details = {"index": index, **exc.details}
                    raise
                results.append((event, False))
                continue
            event = appended.get(key)
            if event is None:
                event = self._new_report_event(item)
                session.add(event)
                await session.flush()
                appended[key] = event
                resolved[key] = event
                results.append((event, True))
            else:
                # Folds onto the event appended for the key's first occurrence in this batch.
                results.append((event, False))
        return results

    def _new_report_event(self, prepared: _PreparedReport) -> Event:
        request = prepared.request
        return self._new_event(
            event_type="report",
            business_key=request.business_key,
            fingerprint=prepared.fingerprint,
            instrument_id=request.instrument_id,
            operator_id=request.operator_id,
            report_digest=prepared.report_digest,
            previous_event_id=None,
        )

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
