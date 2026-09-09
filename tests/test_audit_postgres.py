from __future__ import annotations

import asyncio
import os
from datetime import timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ledger.audit.service import AuditPackageService
from ledger.models import AuditPackage, Base
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
async def test_concurrent_workers_claim_each_package_exactly_once(postgres_url) -> None:
    engine = create_async_engine(postgres_url, pool_size=8)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    service = EventService()
    async with factory() as session:
        for index in range(6):
            await service.append_report(
                session,
                SubmitReport(
                    business_key=f"audit-pg-{index}",
                    instrument_id="INST-PG",
                    operator_id="alice",
                    report={"index": index},
                ),
            )
    async with factory() as session:
        await CheckpointSealer(
            keyring={"v1": TEST_KEY_V1}, current_key_version="v1", batch_size=100
        ).seal_once(session)

    audit = AuditPackageService()
    async with factory() as session:
        package_ids = []
        for index in range(6):
            package, _ = await audit.create_package(
                session,
                instrument_id="INST-PG",
                idempotency_key=f"audit-pg-key-{index}",
            )
            package_ids.append(package.package_id)

    claimed: list = []
    claim_lock = asyncio.Lock()

    async def worker(worker_id: str) -> None:
        async with factory() as session:
            package = await audit.claim_package(
                session,
                worker_id=worker_id,
                lease_duration=timedelta(minutes=5),
            )
        if package is not None:
            async with claim_lock:
                claimed.append((worker_id, package.package_id))

    # Twelve racing attempts for six packages: exactly six distinct claims.
    results = await asyncio.gather(*(worker(f"w{index}") for index in range(12)))
    del results
    assert len(claimed) == 6
    assert {package_id for _, package_id in claimed} == set(package_ids)
    owners = [owner for owner, _ in claimed]
    assert len(set(owners)) >= 2  # SKIP LOCKED distributed the work

    # All claimed rows are building with a single owner each.
    from sqlalchemy import func, select

    async with factory() as session:
        owners_in_db = list(
            await session.scalars(select(AuditPackage.lease_owner).order_by(AuditPackage.id))
        )
        building = await session.scalar(
            select(func.count())
            .select_from(AuditPackage)
            .where(AuditPackage.status == "building")
        )
    assert building == 6
    assert all(owner is not None for owner in owners_in_db)

    # Stale leases after timeout are reclaimable exactly once more.
    from datetime import UTC, datetime
    from datetime import timedelta as td

    async def timed_worker(worker_id: str) -> object:
        async with factory() as session:
            return await audit.claim_package(
                session,
                worker_id=worker_id,
                lease_duration=td(minutes=5),
                now=datetime.now(UTC) + td(minutes=10),
            )

    recovered = await asyncio.gather(*(timed_worker(f"r{index}") for index in range(12)))
    reclaimed = [package for package in recovered if package is not None]
    assert len(reclaimed) == 6
    assert {package.package_id for package in reclaimed} == set(package_ids)
    await engine.dispose()
