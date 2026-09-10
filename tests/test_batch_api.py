from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine

from ledger.api.app import create_app
from ledger.config import Settings
from ledger.models import Base, Event
from ledger.proofs import verify_receipt
from ledger.sealing import CheckpointSealer
from tests.conftest import TEST_KEY_V1


def _payload(key: str, reading: float = 1.0) -> dict:
    return {
        "business_key": key,
        "instrument_id": "INST-BATCH",
        "operator_id": "alice",
        "report": {"reading": reading},
    }


@pytest.fixture
async def client(tmp_path):
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'batch-api.db'}"
    engine = create_async_engine(database_url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    await engine.dispose()
    settings = Settings(
        database_url=database_url,
        hmac_keys_json=json.dumps({"v1": TEST_KEY_V1.decode()}),
        current_key_version="v1",
    )
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            yield SimpleNamespace(client=client, app=app, settings=settings)


@pytest.mark.asyncio
async def test_batch_creates_three_events_with_ordered_results_and_receipts(client) -> None:
    payload = {"reports": [_payload(f"night/a-{i}", reading=1.0 + i) for i in range(3)]}
    response = await client.client.post("/v1/reports/batch", json=payload)
    assert response.status_code == 201
    results = response.json()["results"]
    assert len(results) == 3
    assert [item["created"] for item in results] == [True, True, True]
    assert [item["witness_status"] for item in results] == ["pending"] * 3
    assert [item["event"]["sequence"] for item in results] == [1, 2, 3]
    assert [item["event"]["business_key"] for item in results] == [
        f"night/a-{i}" for i in range(3)
    ]
    for item in results:
        receipt = await client.client.get(f"/v1/events/{item['event']['event_id']}")
        assert receipt.status_code == 200
        body = receipt.json()
        assert body["witness_status"] == "pending"
        assert verify_receipt(body, {"v1": TEST_KEY_V1})["valid"] is True


@pytest.mark.asyncio
async def test_batch_invalid_second_item_returns_index_and_writes_nothing(client) -> None:
    # Encode the body by hand: a strict JSON client rejects the NaN token, while the service
    # canonicalizer must reject it after request parsing.
    body = (
        '{"reports":['
        '{"business_key":"night/valid-1","instrument_id":"INST-BATCH","operator_id":"alice",'
        '"report":{"reading":1.0}},'
        '{"business_key":"night/broken","instrument_id":"INST-BATCH","operator_id":"alice",'
        '"report":{"reading":NaN}}'
        "]}"
    )
    response = await client.client.post(
        "/v1/reports/batch",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "BATCH_ITEM_INVALID"
    assert error["details"]["index"] == 1
    assert error["details"]["business_key"] == "night/broken"
    assert error["request_id"]

    async with client.app.state.session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(Event)) == 0


@pytest.mark.asyncio
async def test_batch_folds_same_content_and_conflicts_on_different_content(client) -> None:
    folded = _payload("night/fold", reading=4.0)
    response = await client.client.post(
        "/v1/reports/batch",
        json={"reports": [folded, _payload("night/alone"), folded]},
    )
    assert response.status_code == 201
    results = response.json()["results"]
    assert [item["created"] for item in results] == [True, True, False]
    assert results[2]["event"]["event_id"] == results[0]["event"]["event_id"]

    conflict = await client.client.post(
        "/v1/reports/batch",
        json={
            "reports": [
                _payload("night/fold", reading=4.0),
                _payload("night/fold", reading=5.0),
            ]
        },
    )
    assert conflict.status_code == 409
    error = conflict.json()["error"]
    assert error["code"] == "IDEMPOTENCY_CONFLICT"
    assert error["details"]["index"] == 1
    assert error["details"]["first_index"] == 0

    against_single = await client.client.post(
        "/v1/reports/batch",
        json={"reports": [_payload("night/alone", reading=99.0)]},
    )
    assert against_single.status_code == 409
    assert against_single.json()["error"]["details"]["index"] == 0


@pytest.mark.asyncio
async def test_full_batch_replay_returns_200_and_single_endpoint_is_unchanged(client) -> None:
    payload = {"reports": [_payload("night/replay-1"), _payload("night/replay-2")]}
    created = await client.client.post("/v1/reports/batch", json=payload)
    replayed = await client.client.post("/v1/reports/batch", json=payload)
    assert created.status_code == 201
    assert replayed.status_code == 200
    assert [item["created"] for item in replayed.json()["results"]] == [False, False]

    single = await client.client.post("/v1/reports", json=_payload("night/single"))
    assert single.status_code == 201
    assert single.json()["event"]["sequence"] == 3
    single_replay = await client.client.post("/v1/reports", json=_payload("night/single"))
    assert single_replay.status_code == 200
    assert single_replay.json()["created"] is False


@pytest.mark.asyncio
async def test_batch_size_boundaries_are_validated(client) -> None:
    too_few = await client.client.post("/v1/reports/batch", json={"reports": []})
    assert too_few.status_code == 422
    assert too_few.json()["error"]["code"] == "INVALID_REQUEST"

    too_many = await client.client.post(
        "/v1/reports/batch",
        json={"reports": [_payload(f"night/oversize-{i}") for i in range(51)]},
    )
    assert too_many.status_code == 422
    violations = too_many.json()["error"]["details"]["violations"]
    assert violations


@pytest.mark.asyncio
async def test_batch_events_seal_and_verify_offline_with_continuous_sequences(client) -> None:
    payload = {"reports": [_payload(f"night/sealed-{i}") for i in range(3)]}
    created = await client.client.post("/v1/reports/batch", json=payload)
    assert created.status_code == 201
    keyring = {"v1": TEST_KEY_V1}
    sealer = CheckpointSealer(keyring=keyring, current_key_version="v1", batch_size=10)
    async with client.app.state.session_factory() as session:
        sealed = await sealer.seal_once(session)
    assert sealed.status == "sealed"
    assert sealed.checkpoint.leaf_count == 3
    for item in created.json()["results"]:
        receipt_response = await client.client.get(
            f"/v1/events/{item['event']['event_id']}"
        )
        receipt = receipt_response.json()
        assert receipt["witness_status"] == "sealed"
        assert verify_receipt(receipt, keyring) == {
            "valid": True,
            "witnessed": True,
            "checkpoint_id": str(sealed.checkpoint.checkpoint_id),
        }


@pytest.mark.asyncio
async def test_batch_event_can_be_revised_and_revoked(client) -> None:
    created = await client.client.post(
        "/v1/reports/batch",
        json={"reports": [_payload("night/lifecycle")]},
    )
    event_id = created.json()["results"][0]["event"]["event_id"]
    revision = await client.client.post(
        f"/v1/events/{event_id}/revisions",
        json={
            "business_key": "night/lifecycle-r2",
            "instrument_id": "INST-BATCH",
            "operator_id": "bob",
            "report": {"reading": 2.0},
        },
    )
    assert revision.status_code == 201
    revision_id = revision.json()["event"]["event_id"]
    revocation = await client.client.post(
        f"/v1/events/{revision_id}/revocations",
        json={
            "business_key": "night/lifecycle-revoke",
            "operator_id": "carol",
            "reason": "reference standard drift",
        },
    )
    assert revocation.status_code == 201
    record = await client.client.get(
        f"/v1/records/{created.json()['results'][0]['event']['record_id']}"
    )
    assert record.status_code == 200
    assert [event["event_type"] for event in record.json()["events"]] == [
        "report",
        "revision",
        "revocation",
    ]
