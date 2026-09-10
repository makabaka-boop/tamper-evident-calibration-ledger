from __future__ import annotations

import asyncio
import math

import pytest
from sqlalchemy import func, select

from ledger.errors import LedgerError
from ledger.models import Event
from ledger.schemas import SubmitReport
from ledger.service import EventService


def _request(key: str, reading: float = 1.0, instrument: str = "CAL-1") -> SubmitReport:
    return SubmitReport(
        business_key=key,
        instrument_id=instrument,
        operator_id="alice",
        report={"reading": reading},
    )


@pytest.mark.asyncio
async def test_three_reports_commit_atomically_with_contiguous_input_ordered_sequences(
    session_factory,
) -> None:
    service = EventService()
    requests = [_request(f"night/00{i}", reading=1.0 + i) for i in range(3)]
    async with session_factory() as session:
        results = await service.append_report_batch(session, requests)

    assert [created for _event, created in results] == [True, True, True]
    keys_in_order = [event.business_key for event, _created in results]
    assert keys_in_order == [request.business_key for request in requests]
    assert [event.sequence for event, _created in results] == [1, 2, 3]
    async with session_factory() as session:
        events = list(
            (await session.scalars(select(Event).order_by(Event.sequence))).all()
        )
    assert [event.business_key for event in events] == keys_in_order
    # Batch events are ordinary report events and remain revisable/queryable.
    assert all(event.event_type == "report" for event in events)
    assert events[0].record_id == events[0].event_id
    assert events[1].previous_event_id is None


@pytest.mark.asyncio
async def test_invalid_second_item_aborts_the_whole_batch_with_zero_writes(
    session_factory,
) -> None:
    service = EventService()
    requests = [
        _request("night/valid-1"),
        SubmitReport(
            business_key="night/non-finite",
            instrument_id="CAL-1",
            operator_id="alice",
            report={"reading": math.nan},
        ),
        _request("night/valid-2"),
    ]
    async with session_factory() as session:
        with pytest.raises(LedgerError) as raised:
            await service.append_report_batch(session, requests)
    assert raised.value.code == "BATCH_ITEM_INVALID"
    assert raised.value.status_code == 422
    assert raised.value.details["index"] == 1
    assert raised.value.details["business_key"] == "night/non-finite"

    async with session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Event)) == 0


@pytest.mark.asyncio
async def test_intra_batch_duplicate_key_with_identical_content_folds_to_one_event(
    session_factory,
) -> None:
    service = EventService()
    request = _request("night/folded", reading=2.5)
    async with session_factory() as session:
        results = await service.append_report_batch(
            session, [request, _request("night/other"), request]
        )

    assert [created for _event, created in results] == [True, True, False]
    folded_event = results[0][0]
    assert results[2][0] is folded_event
    assert results[2][0].sequence == folded_event.sequence
    async with session_factory() as session:
        count = await session.scalar(select(func.count()).select_from(Event))
    assert count == 2
    assert await _key_count(session_factory, "night/folded") == 1


@pytest.mark.asyncio
async def test_intra_batch_duplicate_key_with_different_content_conflicts_and_writes_nothing(
    session_factory,
) -> None:
    service = EventService()
    requests = [
        _request("night/same", reading=1.0),
        _request("night/other"),
        _request("night/same", reading=2.0),
    ]
    async with session_factory() as session:
        with pytest.raises(LedgerError) as raised:
            await service.append_report_batch(session, requests)
    assert raised.value.code == "IDEMPOTENCY_CONFLICT"
    assert raised.value.status_code == 409
    assert raised.value.details["index"] == 2
    assert raised.value.details["first_index"] == 0
    async with session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Event)) == 0


@pytest.mark.asyncio
async def test_committed_key_matching_content_folds_and_different_content_conflicts(
    session_factory,
) -> None:
    service = EventService()
    async with session_factory() as session:
        original, created = await service.append_report(
            session, _request("night/existing", reading=9.0)
        )
    assert created is True

    async with session_factory() as session:
        results = await service.append_report_batch(
            session,
            [
                _request("night/new", reading=3.0),
                _request("night/existing", reading=9.0),
            ],
        )
    assert [created for _event, created in results] == [True, False]
    assert results[1][0].event_id == original.event_id
    assert results[0][0].sequence == 2

    async with session_factory() as session:
        with pytest.raises(LedgerError) as raised:
            await service.append_report_batch(
                session,
                [
                    _request("night/existing", reading=99.0),
                    _request("night/never-written"),
                ],
            )
    assert raised.value.code == "IDEMPOTENCY_CONFLICT"
    assert raised.value.details["index"] == 0
    assert raised.value.details["event_id"] == str(original.event_id)
    async with session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Event)) == 2


@pytest.mark.asyncio
async def test_replaying_an_entire_batch_is_idempotent(session_factory) -> None:
    service = EventService()
    requests = [_request(f"night/replay-{i}") for i in range(3)]
    async with session_factory() as session:
        first = await service.append_report_batch(session, requests)
    async with session_factory() as session:
        second = await service.append_report_batch(session, requests)

    assert all(created for _event, created in first)
    assert all(not created for _event, created in second)
    assert [event.event_id for event, _ in second] == [
        event.event_id for event, _ in first
    ]
    async with session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Event)) == 3


@pytest.mark.asyncio
async def test_folded_key_conflicting_with_committed_content_aborts_batch(
    session_factory,
) -> None:
    service = EventService()
    async with session_factory() as session:
        await service.append_report(session, _request("night/raced", reading=7.0))
    requests = [
        _request("night/raced", reading=7.0),
        _request("night/raced", reading=8.0),
    ]
    async with session_factory() as session:
        with pytest.raises(LedgerError) as raised:
            await service.append_report_batch(session, requests)
    assert raised.value.code == "IDEMPOTENCY_CONFLICT"
    assert raised.value.details["index"] == 1
    assert raised.value.details["first_index"] == 0
    async with session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Event)) == 1


@pytest.mark.asyncio
async def test_first_invalid_index_is_reported_even_when_later_items_also_fail(
    session_factory,
) -> None:
    service = EventService()
    requests = [
        _request("night/ok"),
        SubmitReport(
            business_key="night/nan-1",
            instrument_id="CAL-1",
            operator_id="alice",
            report={"reading": math.nan},
        ),
        SubmitReport(
            business_key="night/inf",
            instrument_id="CAL-1",
            operator_id="alice",
            report={"reading": math.inf},
        ),
    ]
    async with session_factory() as session:
        with pytest.raises(LedgerError) as raised:
            await service.append_report_batch(session, requests)
    assert raised.value.details["index"] == 1


async def _key_count(session_factory, business_key: str) -> int:
    async with session_factory() as session:
        return await session.scalar(
            select(func.count()).select_from(Event).where(Event.business_key == business_key)
        )


@pytest.mark.asyncio
async def test_concurrent_identical_batches_fold_without_gap_or_duplicate(
    tmp_path,
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'race.db'}")
    from ledger.models import Base as _Base

    async with engine.begin() as connection:
        await connection.run_sync(_Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    service = EventService()
    requests = [_request(f"night/race-{index}") for index in range(5)]
    gate = asyncio.Event()

    async def submit():
        async with factory() as session:
            await gate.wait()
            return await service.append_report_batch(session, requests)

    tasks = [asyncio.create_task(submit()) for _ in range(2)]
    gate.set()
    outcomes = await asyncio.gather(*tasks)
    created_flags = [
        sorted(created for _event, created in outcome) for outcome in outcomes
    ]
    assert sorted(created_flags) == [
        [False] * 5,
        [True] * 5,
    ]
    async with factory() as session:
        events = list((await session.scalars(select(Event).order_by(Event.sequence))).all())
    assert [event.sequence for event in events] == [1, 2, 3, 4, 5]
    await engine.dispose()
