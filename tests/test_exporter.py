from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import ledger.exporter as exporter_module
from ledger.audit.service import AuditPackageService
from ledger.models import AuditPackage, AuditPackageArtifact, Base
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
        # WAL lets the API-side cancel writer commit while the worker holds an open read
        # transaction mid-receipt-generation.
        await connection.execute(text("PRAGMA journal_mode=WAL"))
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
        await audit.create_package(session, instrument_id="CAL-EX", idempotency_key="exporter-key")
    await engine.dispose()


@pytest.mark.asyncio
async def test_exporter_loop_builds_package_and_writes_ready_file(tmp_path, monkeypatch) -> None:
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
                    select(AuditPackage.status).where(
                        AuditPackage.idempotency_key == "exporter-key"
                    )
                )
                count = await session.scalar(select(func.count()).select_from(AuditPackageArtifact))
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


@pytest.mark.asyncio
async def test_exporter_honours_cancel_during_build_and_logs_confirmation(
    tmp_path, monkeypatch, caplog
) -> None:
    caplog.set_level(logging.INFO, logger="ledger.exporter")
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'exporter-cancel.db'}"
    await _prepare(database_url)
    ready_file = tmp_path / "ready"
    monkeypatch.setenv("LEDGER_DATABASE_URL", database_url)
    monkeypatch.setenv("LEDGER_HMAC_KEYS_JSON", f'{{"v1":"{KEY_TEXT}"}}')
    monkeypatch.setenv("LEDGER_EXPORT_POLL_SECONDS", "30")
    monkeypatch.setenv("LEDGER_EXPORTER_ID", "cancel-exporter")
    monkeypatch.setenv("LEDGER_EXPORTER_READY_FILE", str(ready_file))
    exporter_module.get_settings.cache_clear()

    gate = asyncio.Event()
    entered = {"once": False}
    original_check = AuditPackageService._check_build_cancelled

    async def gated_check(self, session_factory, claimed) -> None:
        if not entered["once"]:
            entered["once"] = True
            await gate.wait()
        await original_check(self, session_factory, claimed)

    monkeypatch.setattr(AuditPackageService, "_check_build_cancelled", gated_check)

    poll_engine = create_async_engine(database_url)
    poll_factory = async_sessionmaker(poll_engine, expire_on_commit=False)
    audit = AuditPackageService(clock=lambda: FIXED)
    task = asyncio.create_task(exporter_module.run())
    try:
        deadline = datetime.now(UTC) + timedelta(seconds=10)
        while datetime.now(UTC) < deadline:
            async with poll_factory() as session:
                row = await session.get(AuditPackage, 1)
            if row is not None and row.status == "building":
                break
            await asyncio.sleep(0.05)
        else:  # pragma: no cover - failure path
            pytest.fail("package never reached building")

        # Commit the cancellation while the worker is parked inside receipt generation.
        async with poll_factory() as session:
            from sqlalchemy import select

            package = await session.scalar(select(AuditPackage).limit(1))
            package_id = package.package_id
        async with poll_factory() as session:
            cancelled, changed = await audit.cancel_package(session, package_id)
        assert changed is True
        assert cancelled.status == "cancelling"
        gate.set()

        deadline = datetime.now(UTC) + timedelta(seconds=10)
        while datetime.now(UTC) < deadline:
            async with poll_factory() as session:
                from sqlalchemy import func, select

                status = await session.scalar(
                    select(AuditPackage.status).where(
                        AuditPackage.idempotency_key == "exporter-key"
                    )
                )
                count = await session.scalar(select(func.count()).select_from(AuditPackageArtifact))
            if status == "cancelled" and count == 0:
                break
            await asyncio.sleep(0.05)
        else:  # pragma: no cover - failure path
            pytest.fail("worker did not confirm the cancellation")
        assert ready_file.exists()
    finally:
        await poll_engine.dispose()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    confirmations = [
        record.getMessage()
        for record in caplog.records
        if "audit_package_cancel_confirmed" in record.getMessage()
    ]
    assert len(confirmations) == 1
    payload = json.loads(confirmations[0])
    assert payload["event"] == "audit_package_cancel_confirmed"
    assert payload["reason"] == "requested"


@pytest.mark.asyncio
async def test_exporter_restart_converges_legacy_cancelling_task(
    tmp_path, monkeypatch, caplog
) -> None:
    caplog.set_level(logging.INFO, logger="ledger.exporter")
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'exporter-recover.db'}"
    await _prepare(database_url)
    # Simulate a worker that claimed the task, had cancel requested, then crashed forever.
    setup_engine = create_async_engine(database_url)
    setup_factory = async_sessionmaker(setup_engine, expire_on_commit=False)
    audit = AuditPackageService()
    async with setup_factory() as session:
        claimed = await audit.claim_package(
            session,
            worker_id="dead-worker",
            lease_duration=timedelta(seconds=120),
            now=datetime.now(UTC) - timedelta(hours=1),
        )
        assert claimed is not None
        package_id = claimed.package_id
    async with setup_factory() as session:
        cancelled, changed = await audit.cancel_package(session, package_id)
    assert cancelled.status == "cancelling"
    await setup_engine.dispose()

    ready_file = tmp_path / "ready"
    monkeypatch.setenv("LEDGER_DATABASE_URL", database_url)
    monkeypatch.setenv("LEDGER_HMAC_KEYS_JSON", f'{{"v1":"{KEY_TEXT}"}}')
    monkeypatch.setenv("LEDGER_EXPORT_POLL_SECONDS", "30")
    monkeypatch.setenv("LEDGER_EXPORTER_ID", "restart-exporter")
    monkeypatch.setenv("LEDGER_EXPORTER_READY_FILE", str(ready_file))
    exporter_module.get_settings.cache_clear()

    poll_engine = create_async_engine(database_url)
    poll_factory = async_sessionmaker(poll_engine, expire_on_commit=False)
    task = asyncio.create_task(exporter_module.run())
    try:
        deadline = datetime.now(UTC) + timedelta(seconds=10)
        while datetime.now(UTC) < deadline:
            async with poll_factory() as session:
                from sqlalchemy import func, select

                status = await session.scalar(
                    select(AuditPackage.status).where(
                        AuditPackage.idempotency_key == "exporter-key"
                    )
                )
                count = await session.scalar(select(func.count()).select_from(AuditPackageArtifact))
            if status == "cancelled" and count == 0:
                break
            await asyncio.sleep(0.05)
        else:  # pragma: no cover - failure path
            pytest.fail("restarted exporter did not converge the stale cancelling row")
        assert ready_file.exists()
    finally:
        await poll_engine.dispose()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    confirmations = [
        json.loads(record.getMessage())
        for record in caplog.records
        if "audit_package_cancel_confirmed" in record.getMessage()
    ]
    assert len(confirmations) == 1
    assert confirmations[0]["reason"] == "lease_expired"
