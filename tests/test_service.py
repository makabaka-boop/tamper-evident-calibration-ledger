from __future__ import annotations

import math

import pytest
from sqlalchemy import func, select

from ledger.canonical import CanonicalizationError
from ledger.errors import LedgerError
from ledger.models import Event
from ledger.schemas import SubmitReport, SubmitRevision, SubmitRevocation
from ledger.service import EventService


@pytest.mark.asyncio
async def test_idempotency_same_content_returns_original_and_conflict_does_not_append(
    session_factory,
) -> None:
    service = EventService()
    request = SubmitReport(
        business_key="lab-42/import-7",
        instrument_id="CAL-42",
        operator_id="alice",
        report={"result": "accepted", "uncertainty": 0.02},
    )
    async with session_factory() as session:
        first, created = await service.append_report(session, request)
    async with session_factory() as session:
        second, created_again = await service.append_report(session, request)
    assert created is True
    assert created_again is False
    assert second.event_id == first.event_id

    conflicting = request.model_copy(update={"report": {"result": "fail"}})
    async with session_factory() as session:
        with pytest.raises(LedgerError, match="different content") as raised:
            await service.append_report(session, conflicting)
    assert raised.value.code == "IDEMPOTENCY_CONFLICT"
    async with session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Event)) == 1


@pytest.mark.asyncio
async def test_revision_and_revocation_are_new_events_and_history_is_unchanged(
    session_factory,
) -> None:
    service = EventService()
    async with session_factory() as session:
        original, _ = await service.append_report(
            session,
            SubmitReport(
                business_key="r1",
                instrument_id="SCALE-1",
                operator_id="alice",
                report={"mass": 10.001},
            ),
        )
    original_digest = original.report_digest
    async with session_factory() as session:
        revision, _ = await service.append_revision(
            session,
            original.event_id,
            SubmitRevision(
                business_key="r2",
                instrument_id="SCALE-1",
                operator_id="bob",
                report={"mass": 10.002},
            ),
        )
    async with session_factory() as session:
        revoked, _ = await service.append_revocation(
            session,
            revision.event_id,
            SubmitRevocation(
                business_key="r3", operator_id="carol", reason="reference drift discovered"
            ),
        )
    assert revision.previous_event_id == original.event_id
    assert revoked.previous_event_id == revision.event_id
    assert original.record_id == revision.record_id == revoked.record_id
    async with session_factory() as session:
        reloaded = await session.get(Event, original.sequence)
        assert reloaded.report_digest == original_digest
        assert reloaded.event_type == "report"


@pytest.mark.asyncio
async def test_revision_fork_and_instrument_change_are_rejected(session_factory) -> None:
    service = EventService()
    async with session_factory() as session:
        parent, _ = await service.append_report(
            session,
            SubmitReport(
                business_key="base",
                instrument_id="METER-9",
                operator_id="alice",
                report={"value": 9},
            ),
        )
    async with session_factory() as session:
        with pytest.raises(LedgerError) as mismatch:
            await service.append_revision(
                session,
                parent.event_id,
                SubmitRevision(
                    business_key="wrong-instrument",
                    instrument_id="METER-10",
                    operator_id="alice",
                    report={"value": 10},
                ),
            )
    assert mismatch.value.code == "INSTRUMENT_MISMATCH"
    async with session_factory() as session:
        await service.append_revision(
            session,
            parent.event_id,
            SubmitRevision(
                business_key="successor-a",
                instrument_id="METER-9",
                operator_id="alice",
                report={"value": 9.1},
            ),
        )
    async with session_factory() as session:
        with pytest.raises(LedgerError) as fork:
            await service.append_revision(
                session,
                parent.event_id,
                SubmitRevision(
                    business_key="successor-b",
                    instrument_id="METER-9",
                    operator_id="bob",
                    report={"value": 9.2},
                ),
            )
    assert fork.value.code == "EVENT_ALREADY_SUPERSEDED"


@pytest.mark.asyncio
async def test_single_submit_non_finite_report_propagates_canonicalization_error(
    session_factory,
) -> None:
    # The single endpoint must keep its historical behavior: no batch error wrapping, no
    # status change; the canonicalizer error surfaces untouched for the API to render 500.
    service = EventService()
    request = SubmitReport(
        business_key="nan-single",
        instrument_id="CAL-1",
        operator_id="alice",
        report={"reading": math.nan},
    )
    async with session_factory() as session:
        with pytest.raises(CanonicalizationError):
            await service.append_report(session, request)
    async with session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Event)) == 0
