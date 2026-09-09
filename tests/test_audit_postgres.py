from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ledger.audit.service import AuditPackageService
from ledger.errors import LedgerError
from ledger.models import AuditPackage, AuditPackageArtifact, Base
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
            select(func.count()).select_from(AuditPackage).where(AuditPackage.status == "building")
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


@pytest.mark.asyncio
async def test_cancel_and_ready_commit_race_has_single_winner(postgres_url) -> None:
    """Every cancel/ready ordering yields exactly one terminal state and <= one artifact."""

    from sqlalchemy import func, select

    engine = create_async_engine(postgres_url, pool_size=8)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    service = EventService()
    async with factory() as session:
        await service.append_report(
            session,
            SubmitReport(
                business_key="cancel-race-1",
                instrument_id="INST-RACE",
                operator_id="alice",
                report={"reading": 4.2},
            ),
        )
    async with factory() as session:
        await CheckpointSealer(
            keyring={"v1": TEST_KEY_V1}, current_key_version="v1", batch_size=100
        ).seal_once(session)
    audit = AuditPackageService()

    async def claimed_package() -> tuple[object, object]:
        async with factory() as session:
            package, _ = await audit.create_package(
                session,
                instrument_id="INST-RACE",
                idempotency_key=f"race-key-{uuid.uuid4()}",
            )
        async with factory() as session:
            claim = await audit.claim_package(
                session, worker_id="race-worker", lease_duration=timedelta(minutes=5)
            )
        return package, claim

    async def final_state(package, claim) -> tuple[str, int, int]:
        async with factory() as session:
            row = await session.get(AuditPackage, claim.id)
            artifacts = await session.scalar(
                select(func.count())
                .select_from(AuditPackageArtifact)
                .where(AuditPackageArtifact.package_id == package.package_id)
            )
        return row.status, int(artifacts), row.attempt_count

    # Ordering 1: the cancellation commits before the worker reaches the final row lock.
    package_a, claim_a = await claimed_package()
    async with factory() as session:
        from sqlalchemy import update as sa_update

        await session.execute(
            sa_update(AuditPackage)
            .where(AuditPackage.id == claim_a.id)
            .values(status="cancelling", cancel_requested_at=datetime.now(UTC))
        )
        await session.commit()
    assert await audit.build_once(factory, claim_a, {"v1": TEST_KEY_V1}) == "cancelled"
    status_a, artifacts_a, _ = await final_state(package_a, claim_a)
    assert status_a == "cancelled"
    assert artifacts_a == 0
    # Repeat cancellation on the settled row is idempotent rather than conflicting.
    async with factory() as session:
        again, changed = await audit.cancel_package(session, package_a.package_id)
    assert changed is False
    assert again.status == "cancelled"

    # Ordering 2: the worker's ready commit holds the row lock when cancel arrives; once it
    # commits, the queued cancel observes a ready row and fails with 409.
    package_b, claim_b = await claimed_package()
    lock_session = factory()
    await lock_session.execute(
        AuditPackage.__table__.select()
        .where(AuditPackage.package_id == package_b.package_id)
        .with_for_update()
    )
    build_task = asyncio.create_task(audit.build_once(factory, claim_b, {"v1": TEST_KEY_V1}))
    await asyncio.sleep(0.3)  # let build_once block on the row lock

    captured: list[LedgerError] = []

    async def cancel_blocked() -> None:
        async with factory() as session:
            try:
                await audit.cancel_package(session, package_b.package_id)
            except LedgerError as exc:
                captured.append(exc)

    cancel_task = asyncio.create_task(cancel_blocked())
    await asyncio.sleep(0.3)  # cancel now queues behind the same row lock
    await lock_session.rollback()  # release: the worker's READY commit goes first
    assert await build_task == "ready"
    await cancel_task
    await lock_session.close()
    assert len(captured) == 1
    assert captured[0].code == "AUDIT_PACKAGE_ALREADY_READY"
    status_b, artifacts_b, attempts_b = await final_state(package_b, claim_b)
    assert status_b == "ready"
    assert artifacts_b == 1
    assert attempts_b == 1

    await engine.dispose()
