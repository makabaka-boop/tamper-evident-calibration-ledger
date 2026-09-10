from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ledger.coordination import SEALER_ADVISORY_LOCK_ID
from ledger.models import Base, Event
from ledger.proofs import build_receipt, verify_receipt
from ledger.schemas import SubmitReport
from ledger.sealing import CheckpointSealer
from ledger.service import EventService
from tests.conftest import TEST_KEY_V1

pytestmark = pytest.mark.postgres


@pytest.fixture
def postgres_url() -> str:
    value = os.getenv("TEST_DATABASE_URL")
    if not value or not value.startswith("postgresql+asyncpg://"):
        pytest.skip("set TEST_DATABASE_URL to an isolated PostgreSQL database")
    return value


@pytest.mark.asyncio
async def test_concurrent_idempotency_and_sealer_claim_form_one_sequence(postgres_url) -> None:
    engine = create_async_engine(postgres_url, pool_size=5)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    service = EventService()
    request = SubmitReport(
        business_key="concurrent-business-key",
        instrument_id="INST-RACE",
        operator_id="alice",
        report={"reading": 8.125},
    )
    gate = asyncio.Event()

    async def append_after_gate():
        async with factory() as session:
            await gate.wait()
            return await service.append_report(session, request)

    tasks = [asyncio.create_task(append_after_gate()) for _ in range(2)]
    gate.set()
    results = await asyncio.gather(*tasks)
    assert results[0][0].event_id == results[1][0].event_id
    assert sorted(result[1] for result in results) == [False, True]

    sealers = [
        CheckpointSealer(keyring={"v1": TEST_KEY_V1}, current_key_version="v1", batch_size=10)
        for _ in range(2)
    ]

    async def seal(sealer):
        async with factory() as session:
            return await sealer.seal_once(session)

    async with factory() as active_writer:
        async with active_writer.begin():
            await active_writer.execute(
                text("SELECT pg_advisory_xact_lock_shared(:lock_id)"),
                {"lock_id": SEALER_ADVISORY_LOCK_ID},
            )
            blocked = await seal(sealers[0])
            assert blocked.status == "busy"

    seal_results = await asyncio.gather(*(seal(item) for item in sealers))
    assert sum(item.status == "sealed" for item in seal_results) == 1
    assert {item.status for item in seal_results} <= {"sealed", "busy", "idle"}
    await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_batch_and_single_writers_form_a_contiguous_sequence(
    postgres_url,
) -> None:
    engine = create_async_engine(postgres_url, pool_size=10)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    service = EventService()

    def batch_requests(offset: int, count: int) -> list[SubmitReport]:
        return [
            SubmitReport(
                business_key=f"concurrent-batch-{offset}-{index}",
                instrument_id="INST-RACE",
                operator_id="alice",
                report={"reading": offset + index},
            )
            for index in range(count)
        ]

    batch_a = batch_requests(0, 20)
    batch_b = batch_requests(100, 20)
    singles = [
        SubmitReport(
            business_key=f"concurrent-single-{index}",
            instrument_id="INST-RACE",
            operator_id="bob",
            report={"reading": index},
        )
        for index in range(10)
    ]
    gate = asyncio.Event()

    async def write_batch(requests):
        async with factory() as session:
            await gate.wait()
            return await service.append_report_batch(session, requests)

    async def write_single(request):
        async with factory() as session:
            await gate.wait()
            return await service.append_report(session, request)

    tasks = [
        asyncio.create_task(write_batch(batch_a)),
        asyncio.create_task(write_batch(batch_b)),
        *[asyncio.create_task(write_single(request)) for request in singles],
    ]
    gate.set()
    results = await asyncio.gather(*tasks)

    flattened = [
        (event, created)
        for outcome in results
        for event, created in (outcome if isinstance(outcome, list) else [outcome])
    ]
    assert len(flattened) == 50
    assert all(created for _event, created in flattened)

    async with factory() as session:
        sequences = list((await session.scalars(select(Event.sequence))).all())
        count = await session.scalar(select(func.count()).select_from(Event))
        events = list((await session.scalars(select(Event).order_by(Event.sequence))).all())
    assert count == 50
    assert sequences == list(range(1, 51))
    assert sorted(sequences) == sequences

    keyring = {"v1": TEST_KEY_V1}
    sealer = CheckpointSealer(keyring=keyring, current_key_version="v1", batch_size=100)
    async with factory() as session:
        sealed = await sealer.seal_once(session)
    assert sealed.status == "sealed"
    assert sealed.checkpoint.leaf_count == 50
    assert sealed.checkpoint.last_event_sequence == 50

    for event in events:
        async with factory() as session:
            receipt = await build_receipt(session, event.event_id, keyring)
        assert verify_receipt(receipt, keyring)["valid"] is True
    await engine.dispose()
