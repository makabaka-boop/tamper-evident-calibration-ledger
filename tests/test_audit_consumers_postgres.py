from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ledger.audit.consumers import AuditConsumerService
from ledger.errors import LedgerError
from ledger.models import AuditConsumer, Base
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


async def _sealed_chain(factory, *, events: int, batch_size: int) -> int:
    service = EventService()
    async with factory() as session:
        for index in range(events):
            await service.append_report(
                session,
                SubmitReport(
                    business_key=f"consumer-pg-{index}",
                    instrument_id="INST-CONSUMER",
                    operator_id="alice",
                    report={"index": index},
                ),
            )
    checkpoints = 0
    sealer = CheckpointSealer(
        keyring={"v1": TEST_KEY_V1}, current_key_version="v1", batch_size=batch_size
    )
    while True:
        async with factory() as session:
            result = await sealer.seal_once(session)
        if result.status != "sealed":
            break
        checkpoints += 1
    return checkpoints


async def _checkpoint_ids(factory):
    from ledger.models import Checkpoint

    async with factory() as session:
        rows = list(
            await session.scalars(select(Checkpoint).order_by(Checkpoint.leaf_count))
        )
    return [row.checkpoint_id for row in rows]


@pytest.mark.asyncio
async def test_concurrent_acknowledgements_advance_exactly_once_without_rollback(
    postgres_url,
) -> None:
    engine = create_async_engine(postgres_url, pool_size=10)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    assert await _sealed_chain(factory, events=6, batch_size=2) == 3
    checkpoint_ids = await _checkpoint_ids(factory)

    service = AuditConsumerService()
    async with factory() as session:
        consumer, _ = await service.register_consumer(
            session,
            consumer_name="racing-auditor",
            idempotency_key=f"racing-key-{checkpoint_ids[0]}",
        )

    async def acknowledge(checkpoint_id):
        async with factory() as session:
            try:
                await service.acknowledge_checkpoint(
                    session, consumer.consumer_id, checkpoint_id
                )
                return ("ok", checkpoint_id)
            except LedgerError as exc:
                return (exc.code, exc.details["reason"], checkpoint_id)

    # Four concurrent attempts at the genesis checkpoint: exactly one advances.
    genesis_results = await asyncio.gather(
        *(acknowledge(checkpoint_ids[0]) for _ in range(4))
    )
    assert sum(result[0] == "ok" for result in genesis_results) == 1
    assert sorted(result[1] for result in genesis_results if result[0] != "ok") == sorted(
        ["checkpoint_already_acknowledged"] * 3
    )

    # Concurrent attempts for the successor: again exactly one wins, cursor never regresses.
    successor_results = await asyncio.gather(
        *(acknowledge(checkpoint_ids[1]) for _ in range(4))
    )
    assert sum(result[0] == "ok" for result in successor_results) == 1
    losing = [result for result in successor_results if result[0] != "ok"]
    assert all(result[0] == "ACKNOWLEDGEMENT_CONFLICT" for result in losing)
    assert {result[1] for result in losing} == {"checkpoint_already_acknowledged"}

    async with factory() as session:
        final = await service.get_consumer(session, consumer.consumer_id)
        acknowledged_count = await session.scalar(
            select(func.count())
            .select_from(AuditConsumer)
            .where(AuditConsumer.last_checkpoint_id == checkpoint_ids[1])
        )
    assert final.last_checkpoint_id == checkpoint_ids[1]
    assert final.last_acknowledged_at is not None
    assert acknowledged_count == 1
    await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_registration_race_has_one_winner(postgres_url) -> None:
    engine = create_async_engine(postgres_url, pool_size=10)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    service = AuditConsumerService()

    async def register(consumer_name: str):
        async with factory() as session:
            try:
                consumer, created = await service.register_consumer(
                    session,
                    consumer_name=consumer_name,
                    idempotency_key="shared-registration-key",
                )
                return ("ok", created, str(consumer.consumer_id), consumer_name)
            except LedgerError as exc:
                return (exc.code, False, exc.details["consumer_id"], consumer_name)

    # Identical concurrent replays collapse onto one access point.
    same = await asyncio.gather(*(register("same-auditor") for _ in range(3)))
    assert sorted(result[1] for result in same) == [False, False, True]
    assert len({result[2] for result in same}) == 1

    # A different parameter on the same key conflicts and creates no second row.
    different = await asyncio.gather(
        register("different-auditor"),
        register("different-auditor"),
    )
    assert all(result[0] == "IDEMPOTENCY_CONFLICT" for result in different)
    async with factory() as session:
        count = await session.scalar(select(func.count()).select_from(AuditConsumer))
    assert count == 1
    await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_consumers_are_independent(postgres_url) -> None:
    engine = create_async_engine(postgres_url, pool_size=10)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    assert await _sealed_chain(factory, events=4, batch_size=1) == 4
    checkpoint_ids = await _checkpoint_ids(factory)

    service = AuditConsumerService()
    async with factory() as session:
        consumer_a, _ = await service.register_consumer(
            session, consumer_name="auditor-a", idempotency_key="iso-key-a"
        )
        consumer_b, _ = await service.register_consumer(
            session, consumer_name="auditor-b", idempotency_key="iso-key-b"
        )

    async def advance_all(consumer_id):
        outcomes = []
        for cid in checkpoint_ids:
            async with factory() as session:
                await service.acknowledge_checkpoint(session, consumer_id, cid)
                outcomes.append(cid)
        return consumer_id, outcomes

    # Both consumers walk the chain concurrently; each advances its own cursor fully.
    results = await asyncio.gather(
        advance_all(consumer_a.consumer_id),
        advance_all(consumer_b.consumer_id),
    )
    assert len(results) == 2
    assert all(outcomes == checkpoint_ids for _consumer_id, outcomes in results)

    async with factory() as session:
        row_a = await service.get_consumer(session, consumer_a.consumer_id)
        row_b = await service.get_consumer(session, consumer_b.consumer_id)
    assert row_a.last_checkpoint_id == checkpoint_ids[-1]
    assert row_b.last_checkpoint_id == checkpoint_ids[-1]
    await engine.dispose()
