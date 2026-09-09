from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update

from ledger.errors import InvalidProofError, LedgerError
from ledger.models import Event
from ledger.proofs import build_receipt, verify_receipt
from ledger.schemas import SubmitReport
from ledger.sealing import CheckpointSealer
from ledger.service import EventService
from tests.conftest import TEST_KEY_V1, TEST_KEY_V2


@pytest.mark.asyncio
async def test_batch_resume_key_rotation_and_offline_proofs(session_factory) -> None:
    instant = datetime(2026, 1, 1, tzinfo=UTC)
    service = EventService(clock=lambda: instant)
    events = []
    for index in range(5):
        async with session_factory() as session:
            event, _ = await service.append_report(
                session,
                SubmitReport(
                    business_key=f"batch-{index}",
                    instrument_id=f"INST-{index}",
                    operator_id="night-shift",
                    report={"index": index},
                ),
            )
            events.append(event)

    keys = {"v1": TEST_KEY_V1, "v2": TEST_KEY_V2}
    first_sealer = CheckpointSealer(
        keyring=keys,
        current_key_version="v1",
        batch_size=2,
        clock=lambda: instant,
    )
    async with session_factory() as session:
        first = await first_sealer.seal_once(session)
    assert first.status == "sealed"
    assert first.checkpoint.leaf_count == 2
    assert first.checkpoint.key_version == "v1"

    rotated = CheckpointSealer(
        keyring=keys,
        current_key_version="v2",
        batch_size=10,
        clock=lambda: instant + timedelta(minutes=1),
    )
    async with session_factory() as session:
        second = await rotated.seal_once(session)
    assert second.checkpoint.leaf_count == 5
    assert second.checkpoint.previous_checkpoint_id == first.checkpoint.checkpoint_id
    assert second.checkpoint.key_version == "v2"

    async with session_factory() as session:
        receipt = await build_receipt(session, events[4].event_id, keys)
    assert verify_receipt(receipt, keys) == {
        "valid": True,
        "witnessed": True,
        "checkpoint_id": str(second.checkpoint.checkpoint_id),
    }
    assert receipt["consistency_proof"]["old_checkpoint"]["key_version"] == "v1"


@pytest.mark.asyncio
async def test_unsealed_event_is_explicitly_pending(session_factory) -> None:
    service = EventService()
    async with session_factory() as session:
        event, _ = await service.append_report(
            session,
            SubmitReport(
                business_key="pending-1",
                instrument_id="INST-P",
                operator_id="alice",
                report={"result": "accepted"},
            ),
        )
    async with session_factory() as session:
        receipt = await build_receipt(session, event.event_id, {"v1": TEST_KEY_V1})
    assert receipt["witness_status"] == "pending"
    assert receipt["checkpoint"] is None
    assert verify_receipt(receipt, {"v1": TEST_KEY_V1}) == {
        "valid": True,
        "witnessed": False,
    }


@pytest.mark.asyncio
async def test_receipt_tampering_and_unknown_key_are_locatable(session_factory) -> None:
    service = EventService()
    async with session_factory() as session:
        event, _ = await service.append_report(
            session,
            SubmitReport(
                business_key="proof-1",
                instrument_id="INST-P",
                operator_id="alice",
                report={"result": "accepted"},
            ),
        )
    sealer = CheckpointSealer(keyring={"v1": TEST_KEY_V1}, current_key_version="v1", batch_size=10)
    async with session_factory() as session:
        await sealer.seal_once(session)
    async with session_factory() as session:
        receipt = await build_receipt(session, event.event_id, {"v1": TEST_KEY_V1})

    receipt["event"]["report_digest"] = "00" * 32
    with pytest.raises(InvalidProofError, match="commitment hash"):
        verify_receipt(receipt, {"v1": TEST_KEY_V1})

    async with session_factory() as session:
        fresh = await build_receipt(session, event.event_id, {"v1": TEST_KEY_V1})
    with pytest.raises(Exception, match="unknown HMAC key version"):
        verify_receipt(fresh, {"v2": TEST_KEY_V2})

    fresh["checkpoint"]["signature"] = "00" * 32
    with pytest.raises(InvalidProofError, match="HMAC signature"):
        verify_receipt(fresh, {"v1": TEST_KEY_V1})


@pytest.mark.asyncio
async def test_corrupt_stored_commitment_is_reported_with_event_location(session_factory) -> None:
    service = EventService()
    async with session_factory() as session:
        event, _ = await service.append_report(
            session,
            SubmitReport(
                business_key="corrupt-1",
                instrument_id="INST-C",
                operator_id="alice",
                report={"reading": 2.5},
            ),
        )
    # SQLite has no migration trigger, which lets this test emulate damaged restored storage.
    async with session_factory() as session, session.begin():
        await session.execute(
            update(Event).where(Event.event_id == event.event_id).values(leaf_hash="00" * 32)
        )
    async with session_factory() as session:
        with pytest.raises(LedgerError) as raised:
            await build_receipt(session, event.event_id, {"v1": TEST_KEY_V1})
    assert raised.value.code == "MERKLE_NODE_CORRUPT"
    assert raised.value.details["event_id"] == str(event.event_id)
