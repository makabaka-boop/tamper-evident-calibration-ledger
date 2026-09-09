from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from ledger.audit.archive import MANIFEST_NAME, RECEIPTS_DIR, build_archive
from ledger.audit.service import (
    BUILDING,
    FAILED,
    PENDING,
    READY,
    AuditPackageService,
)
from ledger.errors import LedgerError
from ledger.models import AuditPackage
from ledger.proofs import verify_receipt
from ledger.schemas import SubmitReport, SubmitRevision
from ledger.sealing import CheckpointSealer
from ledger.service import EventService
from tests.conftest import TEST_KEY_V1, TEST_KEY_V2

FIXED = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
KEYRING = {"v1": TEST_KEY_V1, "v2": TEST_KEY_V2}


async def _seed_instrument_events(session_factory, *, reports=3, revisions=()):
    service = EventService(clock=lambda: FIXED)
    events = []
    for index in range(reports):
        async with session_factory() as session:
            event, _ = await service.append_report(
                session,
                SubmitReport(
                    business_key=f"report-{index}",
                    instrument_id="CAL-7",
                    operator_id="alice",
                    report={"reading": 1.0 + index},
                ),
            )
            events.append(event)
    for index, parent_index in enumerate(revisions):
        async with session_factory() as session:
            event, _ = await service.append_revision(
                session,
                events[parent_index].event_id,
                SubmitRevision(
                    business_key=f"revision-{index}",
                    instrument_id="CAL-7",
                    operator_id="bob",
                    report={"reading": 2.0 + index},
                ),
            )
            events.append(event)
    return events


async def _seed_other_instrument(session_factory, business_key="other-1"):
    service = EventService(clock=lambda: FIXED)
    async with session_factory() as session:
        event, _ = await service.append_report(
            session,
            SubmitReport(
                business_key=business_key,
                instrument_id="CAL-OTHER",
                operator_id="carol",
                report={"reading": 9.9},
            ),
        )
    return event


async def _seal(session_factory, *, batch_size=100, key_version="v1", at=FIXED):
    sealer = CheckpointSealer(
        keyring=KEYRING,
        current_key_version=key_version,
        batch_size=batch_size,
        clock=lambda: at,
    )
    async with session_factory() as session:
        result = await sealer.seal_once(session)
    return result.checkpoint


@pytest.mark.asyncio
async def test_create_package_pins_latest_sealed_boundary(session_factory) -> None:
    await _seed_instrument_events(session_factory)
    checkpoint = await _seal(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)

    async with session_factory() as session:
        package, created = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="audit-key-1"
        )
    assert created is True
    assert package.status == PENDING
    assert package.checkpoint_id == checkpoint.checkpoint_id
    assert package.attempt_count == 0
    assert package.failure_reason is None


@pytest.mark.asyncio
async def test_replayed_idempotency_key_returns_same_package(session_factory) -> None:
    await _seed_instrument_events(session_factory, reports=1)
    await _seal(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)

    async with session_factory() as session:
        first, created_first = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="replay-key"
        )
    async with session_factory() as session:
        second, created_second = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="replay-key"
        )
    assert created_first is True
    assert created_second is False
    assert first.package_id == second.package_id
    # Replay with the same parameters even after a new checkpoint exists keeps the old row.
    await _seed_other_instrument(session_factory, business_key="other-later")
    await _seal(session_factory, at=FIXED + timedelta(minutes=5))
    async with session_factory() as session:
        replayed, created_third = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="replay-key"
        )
    assert created_third is False
    assert replayed.package_id == first.package_id


@pytest.mark.asyncio
async def test_same_key_with_different_parameters_conflicts(session_factory) -> None:
    await _seed_instrument_events(session_factory, reports=2)
    await _seed_other_instrument(session_factory)
    first_checkpoint = await _seal(session_factory, batch_size=1, at=FIXED)
    # A second, later checkpoint exists so an explicit different boundary can be requested.
    await _seal(session_factory, batch_size=100, at=FIXED + timedelta(minutes=1))
    service = AuditPackageService(clock=lambda: FIXED)

    async with session_factory() as session:
        await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="dup-key"
        )
    # Different instrument reusing the key.
    async with session_factory() as session:
        with pytest.raises(LedgerError) as instrument_conflict:
            await service.create_package(
                session, instrument_id="CAL-OTHER", idempotency_key="dup-key"
            )
    assert instrument_conflict.value.code == "IDEMPOTENCY_CONFLICT"
    assert instrument_conflict.value.status_code == 409
    assert instrument_conflict.value.details["package_id"]
    # Same instrument but an explicit, different checkpoint reusing the key.
    async with session_factory() as session:
        with pytest.raises(LedgerError) as checkpoint_conflict:
            await service.create_package(
                session,
                instrument_id="CAL-7",
                idempotency_key="dup-key",
                checkpoint_id=first_checkpoint.checkpoint_id,
            )
    assert checkpoint_conflict.value.code == "IDEMPOTENCY_CONFLICT"
    # The implicit replay (no checkpoint specified) still returns the original.
    async with session_factory() as session:
        replayed, created = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="dup-key"
        )
    assert created is False
    assert replayed.instrument_id == "CAL-7"


@pytest.mark.asyncio
async def test_missing_seal_and_uncovered_boundaries_return_structured_errors(
    session_factory,
) -> None:
    await _seed_instrument_events(session_factory, reports=1)
    service = AuditPackageService(clock=lambda: FIXED)

    # No checkpoint at all.
    async with session_factory() as session:
        with pytest.raises(LedgerError) as no_checkpoint:
            await service.create_package(
                session, instrument_id="CAL-7", idempotency_key="early-key"
            )
    assert no_checkpoint.value.code == "NO_SEALED_CHECKPOINT"
    assert no_checkpoint.value.status_code == 409

    checkpoint = await _seal(session_factory)
    # Latest checkpoint exists but does not cover a never-seen instrument.
    async with session_factory() as session:
        with pytest.raises(LedgerError) as latest_miss:
            await service.create_package(
                session, instrument_id="GHOST-9", idempotency_key="ghost-key"
            )
    assert latest_miss.value.code == "INSTRUMENT_HAS_NO_SEALED_EVENTS"
    assert latest_miss.value.details["checkpoint_id"] == str(checkpoint.checkpoint_id)

    # Explicit checkpoint that does not cover the instrument.
    async with session_factory() as session:
        with pytest.raises(LedgerError) as explicit_miss:
            await service.create_package(
                session,
                instrument_id="GHOST-9",
                idempotency_key="ghost-explicit",
                checkpoint_id=checkpoint.checkpoint_id,
            )
    assert explicit_miss.value.code == "CHECKPOINT_DOES_NOT_COVER_INSTRUMENT"

    # Unknown checkpoint id keeps the existing not-found envelope.
    from uuid import uuid4

    async with session_factory() as session:
        with pytest.raises(LedgerError) as unknown:
            await service.create_package(
                session,
                instrument_id="CAL-7",
                idempotency_key="missing-checkpoint",
                checkpoint_id=uuid4(),
            )
    assert unknown.value.code == "NOT_FOUND"
    assert unknown.value.status_code == 404


@pytest.mark.asyncio
async def test_boundary_is_isolated_to_events_sealed_before_creation(session_factory) -> None:
    events = await _seed_instrument_events(session_factory, reports=2)
    first_checkpoint = await _seal(session_factory, at=FIXED)
    service = AuditPackageService(clock=lambda: FIXED)
    async with session_factory() as session:
        package, _ = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="boundary-key"
        )

    # Append and seal another event after the package was created.
    later_service = EventService(clock=lambda: FIXED + timedelta(minutes=10))
    async with session_factory() as session:
        later_event, _ = await later_service.append_report(
            session,
            SubmitReport(
                business_key="report-late",
                instrument_id="CAL-7",
                operator_id="dave",
                report={"reading": 5.0},
            ),
        )
    await _seal(session_factory, at=FIXED + timedelta(minutes=20))

    async with session_factory() as session:
        claimed = await service.claim_package(
            session,
            worker_id="w1",
            lease_duration=timedelta(minutes=5),
            now=FIXED,
        )
    status = await service.build_once(session_factory, claimed, KEYRING)
    assert status == READY
    async with session_factory() as session:
        ready = await service.get_package(session, package.package_id)
    assert ready.event_count == 2
    assert ready.status == READY

    from ledger.audit.service import AuditPackageArtifact

    async with session_factory() as session:
        artifact = await session.get(AuditPackageArtifact, package.package_id)
    with zipfile.ZipFile(io.BytesIO(artifact.zip_content)) as archive:
        names = [
            name
            for name in archive.namelist()
            if name.startswith(RECEIPTS_DIR) and name.endswith(".json")
        ]
        manifest = json.loads(archive.read(MANIFEST_NAME))
        included_sequences = {
            json.loads(archive.read(name))["event"]["sequence"] for name in names
        }
    assert included_sequences == {event.sequence for event in events[:2]}
    assert later_event.sequence not in included_sequences
    assert manifest["event_count"] == 2
    assert manifest["boundary"]["checkpoint"]["checkpoint_id"] == str(
        first_checkpoint.checkpoint_id
    )
    assert manifest["boundary"]["last_event_sequence"] == first_checkpoint.last_event_sequence


@pytest.mark.asyncio
async def test_archive_contains_offline_verifiable_receipts_only(session_factory) -> None:
    await _seed_instrument_events(session_factory, reports=3, revisions=(2,))
    await _seal(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    async with session_factory() as session:
        package, _ = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="verify-key"
        )
    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="w1", lease_duration=timedelta(minutes=5)
        )
    await service.build_once(session_factory, claimed, KEYRING)

    from ledger.audit.service import AuditPackageArtifact

    async with session_factory() as session:
        artifact = await session.get(AuditPackageArtifact, package.package_id)
    raw = artifact.zip_content
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert archive.testzip() is None
        names = archive.namelist()
        assert names[0] == RECEIPTS_DIR + "/"
        manifest = json.loads(archive.read(MANIFEST_NAME))
        receipts = []
        for name in names:
            if name.startswith(RECEIPTS_DIR) and name.endswith(".json"):
                receipts.append((name, archive.read(name)))

    # One receipt per event; every receipt verifies fully offline with the auditor keyring.
    assert len(receipts) == manifest["event_count"] == 4
    file_digests = {item["path"]: item["sha256"] for item in manifest["files"]}
    import hashlib

    for name, data in receipts:
        receipt = json.loads(data)
        result = verify_receipt(receipt, KEYRING)
        assert result == {
            "valid": True,
            "witnessed": True,
            "checkpoint_id": manifest["boundary"]["checkpoint"]["checkpoint_id"],
        }
        assert hashlib.sha256(data).hexdigest() == file_digests[name]
        # Public commitment shape only; no raw report content and no key material.
        assert "report" not in receipt["event"]
        assert set(receipt["event"]).isdisjoint({"hmac", "secret", "key"})

    serialized_archive = json.dumps(manifest, sort_keys=True)
    assert TEST_KEY_V1.decode() not in raw.decode("latin-1")
    assert "reading" not in serialized_archive
    assert manifest["boundary"]["checkpoint"]["signature"]
    assert manifest["boundary"]["root_hash"] == manifest["boundary"]["checkpoint"]["root_hash"]


@pytest.mark.asyncio
async def test_rebuilt_archive_from_same_inputs_is_byte_identical(session_factory) -> None:
    await _seed_instrument_events(session_factory, reports=4)
    await _seal(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    async with session_factory() as session:
        package, _ = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="determinism-key"
        )
    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="w1", lease_duration=timedelta(minutes=5)
        )
    await service.build_once(session_factory, claimed, KEYRING)

    from ledger.audit.service import AuditPackageArtifact

    async with session_factory() as session:
        stored = await session.get(AuditPackageArtifact, package.package_id)
        ready = await service.get_package(session, package.package_id)
        bundle = await service._load_bundle(session, ready, KEYRING)

    rebuilt = build_archive(bundle)
    assert rebuilt.content == stored.zip_content
    assert rebuilt.sha256 == stored.sha256 == ready.artifact_sha256
    assert rebuilt.size_bytes == stored.size_bytes
    assert rebuilt.manifest == json.loads(
        zipfile.ZipFile(io.BytesIO(stored.zip_content)).read(MANIFEST_NAME)
    )


@pytest.mark.asyncio
async def test_dual_workers_claim_distinct_packages_without_double_build(
    session_factory,
) -> None:
    await _seed_instrument_events(session_factory, reports=2)
    await _seal(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    async with session_factory() as session:
        package_a, _ = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="job-a"
        )
        package_b, _ = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="job-b"
        )

    async def claim(worker):
        async with session_factory() as session:
            return await service.claim_package(
                session,
                worker_id=worker,
                lease_duration=timedelta(minutes=5),
                now=FIXED,
            )

    first = await claim("w1")
    second = await claim("w2")
    third = await claim("w3")
    claimed_ids = {item.package_id for item in (first, second) if item is not None}
    assert claimed_ids == {package_a.package_id, package_b.package_id}
    assert first.lease_owner != second.lease_owner
    assert third is None
    # Building both claimed jobs completes both with exactly one archive each.
    status_first = await service.build_once(session_factory, first, KEYRING)
    status_second = await service.build_once(session_factory, second, KEYRING)
    assert status_first == READY
    assert status_second == READY
    from sqlalchemy import func, select

    from ledger.models import AuditPackageArtifact

    async with session_factory() as session:
        count = await session.scalar(
            select(func.count()).select_from(AuditPackage).where(AuditPackage.status == READY)
        )
        artifact_count = await session.scalar(
            select(func.count()).select_from(AuditPackageArtifact)
        )
    assert count == 2
    assert artifact_count == 2


@pytest.mark.asyncio
async def test_concurrent_claims_of_one_package_have_a_single_winner(session_factory) -> None:
    import asyncio

    await _seed_instrument_events(session_factory, reports=1)
    await _seal(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    async with session_factory() as session:
        package, _ = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="race-one"
        )

    async def claim(index: int):
        async with session_factory() as session:
            return await service.claim_package(
                session,
                worker_id=f"w{index}",
                lease_duration=timedelta(minutes=5),
                now=FIXED,
            )

    results = await asyncio.gather(*(claim(index) for index in range(8)))
    winners = [candidate for candidate in results if candidate is not None]
    assert len(winners) == 1
    assert winners[0].package_id == package.package_id
    assert winners[0].attempt_count == 1
    assert {candidate.lease_owner for candidate in winners} <= {
        f"w{index}" for index in range(8)
    }


@pytest.mark.asyncio
async def test_crashed_building_lease_is_reclaimed_after_timeout(session_factory) -> None:
    await _seed_instrument_events(session_factory, reports=1)
    await _seal(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    async with session_factory() as session:
        package, _ = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="crash-key"
        )
    async with session_factory() as session:
        crashed = await service.claim_package(
            session,
            worker_id="crashed-worker",
            lease_duration=timedelta(minutes=1),
            now=FIXED,
        )
    assert crashed.status == BUILDING
    # Before timeout nobody can steal the job.
    async with session_factory() as session:
        assert await service.claim_package(
            session,
            worker_id="w2",
            lease_duration=timedelta(minutes=1),
            now=FIXED + timedelta(seconds=30),
        ) is None
    async with session_factory() as session:
        recovered = await service.claim_package(
            session,
            worker_id="w2",
            lease_duration=timedelta(minutes=1),
            now=FIXED + timedelta(seconds=61),
        )
    assert recovered is not None
    assert recovered.lease_owner == "w2"
    assert recovered.attempt_count == 2
    status = await service.build_once(session_factory, recovered, KEYRING)
    assert status == READY
    async with session_factory() as session:
        ready = await service.get_package(session, package.package_id)
    assert ready.status == READY
    assert ready.attempt_count == 2


@pytest.mark.asyncio
async def test_failed_package_records_reason_and_retry_preserves_boundary(
    session_factory,
) -> None:
    await _seed_instrument_events(session_factory, reports=2)
    boundary = await _seal(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    async with session_factory() as session:
        package, _ = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="fail-key"
        )
    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="w1", lease_duration=timedelta(minutes=5)
        )
    # A keyring missing the signing version deterministically fails receipt construction.
    status = await service.build_once(session_factory, claimed, {"v2": TEST_KEY_V2})
    assert status == FAILED
    async with session_factory() as session:
        failed = await service.get_package(session, package.package_id)
    assert failed.status == FAILED
    assert failed.failure_code == "UNKNOWN_KEY_VERSION"
    assert failed.failure_reason
    assert failed.failed_at is not None
    assert failed.lease_owner is None

    async with session_factory() as session:
        retried = await service.request_retry(session, package.package_id)
    assert retried.status == PENDING
    assert retried.checkpoint_id == boundary.checkpoint_id
    assert retried.request_fingerprint == failed.request_fingerprint
    assert retried.failure_reason is None
    assert retried.failure_code is None
    async with session_factory() as session:
        claimed_again = await service.claim_package(
            session, worker_id="w2", lease_duration=timedelta(minutes=5)
        )
    assert claimed_again.attempt_count == 2
    final_status = await service.build_once(session_factory, claimed_again, KEYRING)
    assert final_status == READY
    async with session_factory() as session:
        ready = await service.get_package(session, package.package_id)
    assert ready.checkpoint_id == boundary.checkpoint_id


@pytest.mark.asyncio
async def test_retry_only_applies_to_failed_packages(session_factory) -> None:
    await _seed_instrument_events(session_factory, reports=1)
    await _seal(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    async with session_factory() as session:
        package, _ = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="retry-gate"
        )
    async with session_factory() as session:
        with pytest.raises(LedgerError) as pending_error:
            await service.request_retry(session, package.package_id)
    assert pending_error.value.code == "AUDIT_PACKAGE_NOT_FAILED"

    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="w1", lease_duration=timedelta(minutes=5)
        )
    await service.build_once(session_factory, claimed, KEYRING)
    async with session_factory() as session:
        with pytest.raises(LedgerError) as ready_error:
            await service.request_retry(session, package.package_id)
    assert ready_error.value.code == "AUDIT_PACKAGE_ALREADY_READY"


@pytest.mark.asyncio
async def test_database_error_during_build_does_not_fail_task(session_factory) -> None:
    await _seed_instrument_events(session_factory, reports=1)
    await _seal(session_factory)
    service = AuditPackageService(clock=lambda: FIXED)
    async with session_factory() as session:
        package, _ = await service.create_package(
            session, instrument_id="CAL-7", idempotency_key="db-error-key"
        )

    from sqlalchemy.exc import SQLAlchemyError

    class ExplodingFactory:
        def __call__(self):
            raise SQLAlchemyError("simulated outage")

    async with session_factory() as session:
        claimed = await service.claim_package(
            session, worker_id="w1", lease_duration=timedelta(seconds=1)
        )
    with pytest.raises(SQLAlchemyError):
        await service.build_once(ExplodingFactory(), claimed, KEYRING)
    # Lease still held briefly; after expiry another worker reclaims and completes it.
    async with session_factory() as session:
        recovered = await service.claim_package(
            session,
            worker_id="w2",
            lease_duration=timedelta(minutes=5),
            now=FIXED + timedelta(seconds=2),
        )
    assert recovered.attempt_count == 2
    assert await service.build_once(session_factory, recovered, KEYRING) == READY
