from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import ledger.exporter as exporter_module
from ledger.audit.service import AuditPackageService
from ledger.models import AuditPackageArtifact, Base
from ledger.schemas import SubmitReport
from ledger.sealing import CheckpointSealer
from ledger.service import EventService
from tests.conftest import TEST_KEY_V1

FIXED = datetime(2026, 4, 1, tzinfo=UTC)
KEY_TEXT = TEST_KEY_V1.decode()


async def _prepare(database_url: str) -> None:
    engine = create_async_engine(database_url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    service = EventService(clock=lambda: FIXED)
    async with factory() as session:
        await service.append_report(
            session,
            SubmitReport(
                business_key="exporter-1",
                instrument_id="CAL-EX",
                operator_id="alice",
                report={"reading": 3.0},
            ),
        )
    async with factory() as session:
        await CheckpointSealer(
            keyring={"v1": TEST_KEY_V1},
            current_key_version="v1",
            batch_size=100,
            clock=lambda: FIXED,
        ).seal_once(session)
    audit = AuditPackageService(clock=lambda: FIXED)
    async with factory() as session:
        await audit.create_package(
            session, instrument_id="CAL-EX", idempotency_key="exporter-key"
        )
    await engine.dispose()


@pytest.mark.asyncio
async def test_exporter_loop_builds_package_and_writes_ready_file(
    tmp_path, monkeypatch
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'exporter.db'}"
    await _prepare(database_url)
    ready_file = tmp_path / "ready"
    monkeypatch.setenv("LEDGER_DATABASE_URL", database_url)
    monkeypatch.setenv("LEDGER_HMAC_KEYS_JSON", f'{{"v1":"{KEY_TEXT}"}}')
    monkeypatch.setenv("LEDGER_EXPORT_POLL_SECONDS", "30")
    monkeypatch.setenv("LEDGER_EXPORTER_ID", "test-exporter")
    monkeypatch.setenv("LEDGER_EXPORTER_READY_FILE", str(ready_file))
    exporter_module.get_settings.cache_clear()

    from sqlalchemy import func, select

    from ledger.models import AuditPackage

    task = asyncio.create_task(exporter_module.run())
    poll_engine = create_async_engine(database_url)
    poll_factory = async_sessionmaker(poll_engine, expire_on_commit=False)
    try:
        deadline = datetime.now(UTC) + timedelta(seconds=10)
        while datetime.now(UTC) < deadline:
            async with poll_factory() as session:
                status = await session.scalar(
                    select(AuditPackage.status)
                    .where(AuditPackage.idempotency_key == "exporter-key")
                )
                count = await session.scalar(
                    select(func.count()).select_from(AuditPackageArtifact)
                )
            if status == "ready" and count == 1:
                break
            await asyncio.sleep(0.1)
        else:  # pragma: no cover - failure path
            pytest.fail("exporter did not finish the package in time")
        assert ready_file.exists()
    finally:
        await poll_engine.dispose()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert not ready_file.exists()
