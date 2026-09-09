from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from ledger.audit.service import (
    BUILDING,
    CANCELING,
    CANCELLED,
    FAILED,
    READY,
    SUPERSEDED,
    AuditPackageService,
)
from ledger.errors import LedgerError
from ledger.models import AuditPackage, AuditPackageArtifact
from ledger.proofs import verify_receipt
from ledger.schemas import SubmitReport
from ledger.sealing import CheckpointSealer
from ledger.service import EventService
from tests.conftest import TEST_KEY_V1, TEST_KEY_V2

FIXED = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
KEYRING = {"v1": TEST_KEY_V1, "v2": TEST_KEY_V2}


async def _prepare(session_factory, *, reports=5, instrument="CAL-CANCEL", key="seal"):
    events = EventService(clock=lambda: FIXED)
    for index in range(reports):
        async with session_factory() as session:
            event, _ = await events.append_report(
                session,
                SubmitReport(
                    business_key=f"{key}-report-{index}",
                    instrument_id=instrument,
                    operator_id="alice",
                    report={"reading": 1.0 + index},
                ),
            )
    sealer = CheckpointSealer(
        keyring=KEYRING, current_key_version="v1", batch_size=100, clock=lambda: FIXED
    )
    async with session_factory() as session:
        checkpoint = (await sealer.seal_once(session)).checkpoint
    return checkpoint


async def _create(session_factory, service, idem="cancel-job", instrument="CAL-CANCEL"):
    async with session_factory() as session:
        package, _ = await service.create_package(
            session, instrument_id=instrument, idempotency_key=idem
        )
    return package


def _artifact_count(session_factory):
    async def count() -> int:
        async with session_factory() as session:
            return int(await session.scalar(select(func.count()).select_from(AuditPackageArtifact)))

    return count()


def _as_utc(value: datetime) -> datetime:
    # SQLite round-trips timezone-aware timestamps without their tzinfo.
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


async def _reload(session_factory, package) -> AuditPackage:
    async with session_factory() as session:
        return await session.get(AuditPackage, package.id)


class CooperativeCancelService(AuditPackageService):
    """Service that commits a cancellation when the build reaches a chosen check point."""

    def __init__(self, *, flip_on_check: int, **kwargs) -> None:
        super().__init__(**kwargs)
        self.flip_on_check = flip_on_check
        self.checks = 0

    async def _check_build_cancelled(self, session_factory, claimed) -> None:
        await super()._check_build_cancelled(session_factory, claimed)
        self.checks += 1
        if self.checks == self.flip_on_check:
            async with session_factory() as cancel_session:
                await self.cancel_package(cancel_session, claimed.package_id)


class ObliviousBuildService(AuditPackageService):
    """Service whose receipt-phase checks never observe cancellation (write lock still does)."""

    async def _check_build_cancelled(self, session_factory, claimed) -> None:
        return None


@pytest.mark.asyncio
async def test_pending_cancel_is_immediate_and_idempotent(session_factory) -> None:
    await _prepare(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    package = await _create(session_factory, service)

    async with session_factory() as session:
        cancelled, changed = await service.cancel_package(session, package.package_id)
    assert changed is True
    assert cancelled.status == CANCELLED
    assert _as_utc(cancelled.cancel_requested_at) == FIXED
    assert _as_utc(cancelled.cancelled_at) == FIXED
    assert cancelled.lease_owner is None
    assert cancelled.attempt_count == 0
    assert cancelled.event_count is None

    # A repeated cancel returns the current task and performs no further state change.
    later = FIXED + timedelta(minutes=10)
    service.clock = lambda: later
    async with session_factory() as session:
        again, changed_again = await service.cancel_package(session, package.package_id)
    assert changed_again is False
    assert again.status == CANCELLED
    assert _as_utc(again.cancel_requested_at) == FIXED
    assert _as_utc(again.cancelled_at) == FIXED
    assert _as_utc(again.updated_at) == FIXED
    assert await _artifact_count(session_factory) == 0
    # A cancelled task is never claimed by a worker.
    async with session_factory() as session:
        assert (
            await service.claim_package(
                session, worker_id="w1", lease_duration=timedelta(minutes=5)
            )
            is None
        )


@pytest.mark.asyncio
async def test_building_cancel_during_receipt_generation_abandons_result(
    session_factory,
) -> None:
    await _prepare(session_factory, reports=5)
    # Flip after the second per-receipt observation: two receipts exist only in memory, the
    # remaining three must never be computed, and no artifact is ever written.
    service = CooperativeCancelService(flip_on_check=4, clock=lambda: FIXED)
    package = await _create(session_factory, service)
    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="w1", lease_duration=timedelta(minutes=5), now=FIXED
        )
    assert claimed.status == BUILDING

    status = await service.build_once(session_factory, claimed, KEYRING)
    assert status == CANCELLED
    final = await _reload(session_factory, package)
    assert final.status == CANCELLED
    assert _as_utc(final.cancel_requested_at) == FIXED
    assert _as_utc(final.cancelled_at) == FIXED
    assert final.lease_owner is None
    assert final.lease_expires_at is None
    # Fixed identity, boundary and attempt accounting are untouched.
    assert final.attempt_count == 1
    assert final.event_count is None
    assert final.artifact_sha256 is None
    assert await _artifact_count(session_factory) == 0

    # Repeat cancel after worker confirmation stays idempotent.
    async with session_factory() as session:
        again, changed = await service.cancel_package(session, package.package_id)
    assert changed is False
    assert again.status == CANCELLED
    assert _as_utc(again.cancelled_at) == FIXED


@pytest.mark.asyncio
async def test_cancel_committed_after_receipts_is_stopped_at_artifact_write(
    session_factory,
) -> None:
    await _prepare(session_factory)
    service = ObliviousBuildService(clock=lambda: FIXED)
    package = await _create(session_factory, service)
    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="w1", lease_duration=timedelta(minutes=5), now=FIXED
        )
    # Cancellation lands while the receipt bundle is being rendered; cooperative checks are
    # bypassed so the write-transaction row lock is the deciding barrier.
    async with session_factory() as session:
        cancelling, changed = await service.cancel_package(session, package.package_id)
    assert changed is True
    assert cancelling.status == CANCELING
    assert _as_utc(cancelling.cancel_requested_at) == FIXED
    assert cancelling.cancelled_at is None
    assert cancelling.lease_owner == "w1"

    status = await service.build_once(session_factory, claimed, KEYRING)
    assert status == CANCELLED
    final = await _reload(session_factory, package)
    assert final.status == CANCELLED
    assert _as_utc(final.cancelled_at) == FIXED
    assert final.event_count is None
    assert await _artifact_count(session_factory) == 0


@pytest.mark.asyncio
async def test_ready_commit_wins_against_cancel_at_row_lock(session_factory) -> None:
    """Without a committed cancellation the worker's ready transition completes normally."""

    await _prepare(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    package = await _create(session_factory, service)
    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="w1", lease_duration=timedelta(minutes=5), now=FIXED
        )
    assert await service.build_once(session_factory, claimed, KEYRING) == READY
    async with session_factory() as session:
        with pytest.raises(LedgerError) as conflict:
            await service.cancel_package(session, package.package_id)
    assert conflict.value.code == "AUDIT_PACKAGE_ALREADY_READY"
    assert conflict.value.status_code == 409
    assert conflict.value.details["status"] == READY
    # The ready row and its immutable artifact survive the rejected cancel.
    final = await _reload(session_factory, package)
    assert final.status == READY
    assert final.cancel_requested_at is None
    assert await _artifact_count(session_factory) == 1


@pytest.mark.asyncio
async def test_failed_package_cancel_is_rejected(session_factory) -> None:
    await _prepare(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    package = await _create(session_factory, service)
    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="bad", lease_duration=timedelta(minutes=5), now=FIXED
        )
    assert await service.build_once(session_factory, claimed, {"v9": TEST_KEY_V1}) == FAILED
    async with session_factory() as session:
        with pytest.raises(LedgerError) as conflict:
            await service.cancel_package(session, package.package_id)
    assert conflict.value.code == "AUDIT_PACKAGE_NOT_CANCELLABLE"
    assert conflict.value.status_code == 409
    assert conflict.value.details["status"] == FAILED


@pytest.mark.asyncio
async def test_settle_stale_cancelling_converges_dead_worker_tasks(
    session_factory,
) -> None:
    await _prepare(session_factory, reports=1)
    service = AuditPackageService(clock=lambda: FIXED)
    live_package = await _create(session_factory, service, idem="live-cancelling")
    stale_package = await _create(session_factory, service, idem="stale-cancelling")

    async def claim_and_cancel(pkg, *, lease_seconds=60):
        async with session_factory() as session:
            claimed = await service.claim_package(
                session,
                worker_id="dead-worker",
                lease_duration=timedelta(seconds=lease_seconds),
                now=FIXED,
            )
            assert claimed.package_id == pkg.package_id
        async with session_factory() as session:
            await service.cancel_package(session, pkg.package_id)

    await claim_and_cancel(live_package, lease_seconds=300)
    await claim_and_cancel(stale_package, lease_seconds=30)

    # Before the short lease expires the cancelling rows are neither settled nor reclaimed.
    async with session_factory() as session:
        settled_now = await service.settle_stale_cancelling(session, now=FIXED)
    assert settled_now == []
    async with session_factory() as session:
        assert (
            await service.claim_package(
                session,
                worker_id="w2",
                lease_duration=timedelta(minutes=5),
                now=FIXED + timedelta(seconds=20),
            )
            is None
        )

    # After the lease expiry a restarting/healthy worker converges the dead task once.
    async with session_factory() as session:
        settled = await service.settle_stale_cancelling(session, now=FIXED + timedelta(seconds=31))
    assert [item.package_id for item in settled] == [stale_package.package_id]
    stale_row = await _reload(session_factory, stale_package)
    live_row = await _reload(session_factory, live_package)
    assert stale_row.status == CANCELLED
    assert _as_utc(stale_row.cancelled_at) == FIXED + timedelta(seconds=31)
    assert stale_row.lease_owner is None
    assert stale_row.attempt_count == 1  # attempts are not rewritten by convergence
    assert live_row.status == CANCELING
    # A second settle pass changes nothing until the surviving lease also expires.
    async with session_factory() as session:
        assert (
            await service.settle_stale_cancelling(session, now=FIXED + timedelta(seconds=60)) == []
        )
    assert (await _reload(session_factory, live_row)).status == CANCELING
    async with session_factory() as session:
        second = await service.settle_stale_cancelling(session, now=FIXED + timedelta(seconds=301))
    assert [item.package_id for item in second] == [live_package.package_id]
    assert (await _reload(session_factory, live_row)).status == CANCELLED


@pytest.mark.asyncio
async def test_ghost_worker_after_stale_settle_does_not_confirm_or_rebuild(
    session_factory,
) -> None:
    await _prepare(session_factory, reports=1)
    service = AuditPackageService(clock=lambda: FIXED)
    package = await _create(session_factory, service, idem="ghost-job")
    # The original claim uses a short lease, then cancel lands before the "slow" worker
    # produces anything.
    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="slow-worker", lease_duration=timedelta(seconds=30), now=FIXED
        )
    async with session_factory() as session:
        await service.cancel_package(session, package.package_id)
    # The worker dies long enough for the lease to expire; a healthy worker settles it.
    async with session_factory() as session:
        settled = await service.settle_stale_cancelling(
            session, now=FIXED + timedelta(seconds=31)
        )
    assert [item.package_id for item in settled] == [package.package_id]

    # The zombie worker resumes and completes its build_once: no artifact, no second
    # confirmation transition; the reported result marks the claim as superseded.
    assert await service.build_once(session_factory, claimed, KEYRING) == SUPERSEDED
    final = await _reload(session_factory, package)
    assert final.status == CANCELLED
    assert _as_utc(final.cancelled_at) == FIXED + timedelta(seconds=31)
    assert final.attempt_count == 1
    assert await _artifact_count(session_factory) == 0


@pytest.mark.asyncio
async def test_download_and_retry_gates_for_cancelled_states(session_factory) -> None:
    await _prepare(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    cancelled_pkg = await _create(session_factory, service, idem="cancelled-gate")
    cancelling_pkg = await _create(session_factory, service, idem="cancelling-gate")

    async with session_factory() as session:
        await service.cancel_package(session, cancelled_pkg.package_id)
    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="w1", lease_duration=timedelta(minutes=5), now=FIXED
        )
        assert claimed.package_id == cancelling_pkg.package_id
    async with session_factory() as session:
        await service.cancel_package(session, cancelling_pkg.package_id)

    for pkg, status_name in (
        (cancelled_pkg, CANCELLED),
        (cancelling_pkg, CANCELING),
    ):
        async with session_factory() as session:
            with pytest.raises(LedgerError) as download_error:
                await service.get_ready_artifact(session, pkg.package_id)
        assert download_error.value.code == "AUDIT_PACKAGE_NOT_READY"
        assert download_error.value.status_code == 409
        assert download_error.value.details["status"] == status_name
        assert download_error.value.details["retryable"] is False
        async with session_factory() as session:
            with pytest.raises(LedgerError) as retry_error:
                await service.request_retry(session, pkg.package_id)
        assert retry_error.value.code == "AUDIT_PACKAGE_NOT_RETRYABLE"
        assert retry_error.value.status_code == 409
        assert retry_error.value.details["status"] == status_name
        assert retry_error.value.details["retryable"] is False


@pytest.mark.asyncio
async def test_unknown_cancel_uses_not_found_envelope(session_factory) -> None:
    import uuid

    service = AuditPackageService(clock=lambda: FIXED)
    async with session_factory() as session:
        with pytest.raises(LedgerError) as missing:
            await service.cancel_package(session, uuid.uuid4())
    assert missing.value.code == "NOT_FOUND"
    assert missing.value.status_code == 404
    assert missing.value.details["entity"] == "audit_package"


@pytest.mark.asyncio
async def test_uncancelled_package_still_builds_deterministic_verified_zip(
    session_factory,
) -> None:
    """Regression: a cancelled sibling does not affect a normal package's byte output."""

    await _prepare(session_factory, reports=3)
    service = AuditPackageService(clock=lambda: FIXED)
    doomed = await _create(session_factory, service, idem="doomed")
    keeper = await _create(session_factory, service, idem="keeper")
    async with session_factory() as session:
        await service.cancel_package(session, doomed.package_id)

    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="w1", lease_duration=timedelta(minutes=5), now=FIXED
        )
    assert claimed.package_id == keeper.package_id
    assert await service.build_once(session_factory, claimed, KEYRING) == READY

    from ledger.audit.archive import MANIFEST_NAME, RECEIPTS_DIR, build_archive

    async with session_factory() as session:
        stored = await session.get(AuditPackageArtifact, keeper.package_id)
        ready = await service.get_package(session, keeper.package_id)
        bundle = await service._load_bundle(session, ready, KEYRING)
    rebuilt = build_archive(bundle)
    assert rebuilt.content == stored.zip_content
    assert rebuilt.sha256 == stored.sha256 == ready.artifact_sha256

    with zipfile.ZipFile(io.BytesIO(stored.zip_content)) as archive:
        manifest = json.loads(archive.read(MANIFEST_NAME))
        names = [
            name
            for name in archive.namelist()
            if name.startswith(RECEIPTS_DIR) and name.endswith(".json")
        ]
        for name in names:
            receipt = json.loads(archive.read(name))
            assert verify_receipt(receipt, KEYRING)["valid"] is True
    assert manifest["event_count"] == len(names) == 3
    assert await _artifact_count(session_factory) == 1
