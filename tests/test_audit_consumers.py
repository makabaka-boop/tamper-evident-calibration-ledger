from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ledger.api.app import create_app
from ledger.config import Settings
from ledger.models import Base
from ledger.schemas import SubmitReport
from ledger.sealing import CheckpointSealer
from ledger.service import EventService
from tests.conftest import TEST_KEY_V1

FIXED = datetime(2026, 7, 1, tzinfo=UTC)
KEY_TEXT = TEST_KEY_V1.decode()
KEYRING = {"v1": TEST_KEY_V1}
# Three checkpoints covering sequences 1-3, 4-7, and 8-9 respectively.
_BATCH_SIZES = (3, 4, 2)


async def _sealed_database(database_url: str) -> list[dict[str, object]]:
    engine = create_async_engine(database_url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    service = EventService(clock=lambda: FIXED)
    sealer = CheckpointSealer(
        keyring=KEYRING, current_key_version="v1", batch_size=100, clock=lambda: FIXED
    )
    checkpoints: list[dict[str, object]] = []
    sequence = 0
    for count in _BATCH_SIZES:
        async with factory() as session:
            for _ in range(count):
                sequence += 1
                await service.append_report(
                    session,
                    SubmitReport(
                        business_key=f"consumer-incr-{sequence}",
                        instrument_id="CAL-CONSUMER",
                        operator_id="alice",
                        report={"reading": sequence},
                    ),
                )
        async with factory() as session:
            result = await sealer.seal_once(session)
        assert result.status == "sealed"
        assert result.checkpoint is not None
        checkpoints.append(
            {
                "checkpoint_id": str(result.checkpoint.checkpoint_id),
                "last_event_sequence": result.checkpoint.last_event_sequence,
                "leaf_count": result.checkpoint.leaf_count,
            }
        )
    await engine.dispose()
    return checkpoints


def _app(database_url: str) -> object:
    return create_app(
        Settings(
            database_url=database_url,
            hmac_keys_json=json.dumps({"v1": KEY_TEXT}),
            current_key_version="v1",
        )
    )


def test_cursor_compare_and_set_compiles_to_portable_sql() -> None:
    # Regression: ``column IS :non_null`` parses in SQLite but is a syntax error in
    # PostgreSQL, which surfaced as a 503 when acknowledging the checkpoint after genesis.
    # The non-null predecessor branch must render an equality; genesis uses IS NULL.
    from sqlalchemy import update
    from sqlalchemy.dialects import postgresql, sqlite

    from ledger.audit.consumers import _cursor_matches
    from ledger.models import AuditConsumer

    predecessor = uuid.UUID("11111111-1111-1111-1111-111111111111")
    successor_id = uuid.UUID("22222222-2222-2222-2222-222222222222")

    advance = update(AuditConsumer).where(
        AuditConsumer.id == 1, _cursor_matches(predecessor)
    ).values(last_checkpoint_id=successor_id)
    genesis = update(AuditConsumer).where(
        AuditConsumer.id == 1, _cursor_matches(None)
    ).values(last_checkpoint_id=successor_id)

    for dialect in (postgresql.dialect(), sqlite.dialect()):
        advance_sql = str(
            advance.compile(dialect=dialect, compile_kwargs={"literal_binds": True})
        )
        # Equality on the populated predecessor; never a bare ``IS '<value>'``.
        assert "last_checkpoint_id = " in advance_sql
        assert "last_checkpoint_id IS '" not in advance_sql
        genesis_sql = str(
            genesis.compile(dialect=dialect, compile_kwargs={"literal_binds": True})
        )
        assert "last_checkpoint_id IS NULL" in genesis_sql


@pytest.mark.asyncio
async def test_registration_replay_returns_same_object_and_conflicts_on_other_params(
    tmp_path,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'consumers-register.db'}"
    await _sealed_database(database_url)
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    payload = {"consumer_name": "external-auditor-1", "idempotency_key": "consumer-key-1"}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            created = await client.post("/v1/audit-consumers", json=payload)
            replayed = await client.post("/v1/audit-consumers", json=payload)
            conflict = await client.post(
                "/v1/audit-consumers",
                json={"consumer_name": "external-auditor-2", "idempotency_key": "consumer-key-1"},
            )

    assert created.status_code == 201
    assert created.json()["created"] is True
    first = created.json()["consumer"]
    assert first["consumer_name"] == "external-auditor-1"
    assert first["last_acknowledged_checkpoint"] is None
    assert first["created_at"] == first["updated_at"]
    assert first["consumer_id"]

    assert replayed.status_code == 200
    assert replayed.json()["created"] is False
    assert replayed.json()["consumer"] == first

    assert conflict.status_code == 409
    body = conflict.json()["error"]
    assert body["code"] == "IDEMPOTENCY_CONFLICT"
    assert body["details"]["idempotency_key"] == "consumer-key-1"
    assert body["details"]["consumer_id"] == first["consumer_id"]
    assert body["details"]["consumer_name"] == "external-auditor-1"
    assert body["request_id"]


@pytest.mark.asyncio
async def test_acknowledgements_follow_the_checkpoint_chain_in_order(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'consumers-order.db'}"
    checkpoints = await _sealed_database(database_url)
    first_id, second_id, third_id = (item["checkpoint_id"] for item in checkpoints)
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            registered = await client.post(
                "/v1/audit-consumers",
                json={"consumer_name": "ordered-auditor", "idempotency_key": "order-key"},
            )
            consumer_id = registered.json()["consumer"]["consumer_id"]

            # Skipping the genesis checkpoint on the first acknowledgement is rejected.
            skipped_first = await client.post(
                f"/v1/audit-consumers/{consumer_id}/acknowledgements",
                json={"checkpoint_id": second_id},
            )
            assert skipped_first.status_code == 409
            error = skipped_first.json()["error"]
            assert error["code"] == "ACKNOWLEDGEMENT_CONFLICT"
            details = error["details"]
            assert details["reason"] == "checkpoint_is_not_first"
            assert details["current_checkpoint_id"] is None
            assert details["expected_predecessor_checkpoint_id"] is None
            assert details["submitted_checkpoint_id"] == second_id
            assert details["submitted_leaf_count"] == 7

            ack_first = await client.post(
                f"/v1/audit-consumers/{consumer_id}/acknowledgements",
                json={"checkpoint_id": first_id},
            )
            assert ack_first.status_code == 201
            body = ack_first.json()
            assert body["advanced"] is True
            assert body["acknowledgement"]["checkpoint_id"] == first_id
            assert body["acknowledgement"]["leaf_count"] == 3
            assert body["acknowledgement"]["last_event_sequence"] == 3
            assert body["consumer"]["last_acknowledged_checkpoint"]["checkpoint_id"] == first_id
            assert body["consumer"]["last_acknowledged_checkpoint"]["leaf_count"] == 3

            # Re-acknowledging the same checkpoint is a duplicate conflict.
            duplicate = await client.post(
                f"/v1/audit-consumers/{consumer_id}/acknowledgements",
                json={"checkpoint_id": first_id},
            )
            assert duplicate.status_code == 409
            duplicate_details = duplicate.json()["error"]["details"]
            assert duplicate_details["reason"] == "checkpoint_already_acknowledged"
            assert duplicate_details["current_checkpoint_id"] == first_id
            assert duplicate_details["expected_predecessor_checkpoint_id"] == first_id

            # Jumping two checkpoints ahead is a skip conflict naming the expected predecessor.
            jumped = await client.post(
                f"/v1/audit-consumers/{consumer_id}/acknowledgements",
                json={"checkpoint_id": third_id},
            )
            assert jumped.status_code == 409
            jumped_details = jumped.json()["error"]["details"]
            assert jumped_details["reason"] == "checkpoint_is_not_successor"
            assert jumped_details["current_checkpoint_id"] == first_id
            assert jumped_details["expected_predecessor_checkpoint_id"] == first_id
            assert jumped_details["submitted_checkpoint_id"] == third_id

            ack_second = await client.post(
                f"/v1/audit-consumers/{consumer_id}/acknowledgements",
                json={"checkpoint_id": second_id},
            )
            assert ack_second.status_code == 201
            assert (
                ack_second.json()["consumer"]["last_acknowledged_checkpoint"]["checkpoint_id"]
                == second_id
            )

            # A backwards acknowledgement is rejected and leaves the cursor at the successor.
            backwards = await client.post(
                f"/v1/audit-consumers/{consumer_id}/acknowledgements",
                json={"checkpoint_id": first_id},
            )
            assert backwards.status_code == 409
            back_details = backwards.json()["error"]["details"]
            assert back_details["reason"] == "checkpoint_precedes_current"
            assert back_details["current_checkpoint_id"] == second_id
            assert back_details["expected_predecessor_checkpoint_id"] == second_id

            ack_third = await client.post(
                f"/v1/audit-consumers/{consumer_id}/acknowledgements",
                json={"checkpoint_id": third_id},
            )
            assert ack_third.status_code == 201

            fetched = await client.get(f"/v1/audit-consumers/{consumer_id}")
            assert fetched.status_code == 200
            current = fetched.json()["consumer"]["last_acknowledged_checkpoint"]
            assert current["checkpoint_id"] == third_id
            assert current["leaf_count"] == 9
            assert current["last_event_sequence"] == 9
            assert current["acknowledged_at"]


@pytest.mark.asyncio
async def test_multiple_consumers_advance_independently(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'consumers-isolation.db'}"
    checkpoints = await _sealed_database(database_url)
    first_id, second_id, _third_id = (item["checkpoint_id"] for item in checkpoints)
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            ahead = await client.post(
                "/v1/audit-consumers",
                json={"consumer_name": "auditor-ahead", "idempotency_key": "ahead-key"},
            )
            behind = await client.post(
                "/v1/audit-consumers",
                json={"consumer_name": "auditor-behind", "idempotency_key": "behind-key"},
            )
            ahead_id = ahead.json()["consumer"]["consumer_id"]
            behind_id = behind.json()["consumer"]["consumer_id"]
            assert ahead_id != behind_id

            for checkpoint_id in (first_id, second_id):
                response = await client.post(
                    f"/v1/audit-consumers/{ahead_id}/acknowledgements",
                    json={"checkpoint_id": checkpoint_id},
                )
                assert response.status_code == 201

            # The second consumer still starts at the genesis checkpoint.
            late_genesis = await client.post(
                f"/v1/audit-consumers/{behind_id}/acknowledgements",
                json={"checkpoint_id": second_id},
            )
            assert late_genesis.status_code == 409
            assert (
                late_genesis.json()["error"]["details"]["reason"] == "checkpoint_is_not_first"
            )

            behind_first = await client.post(
                f"/v1/audit-consumers/{behind_id}/acknowledgements",
                json={"checkpoint_id": first_id},
            )
            assert behind_first.status_code == 201

            ahead_view = (await client.get(f"/v1/audit-consumers/{ahead_id}")).json()["consumer"]
            behind_view = (await client.get(f"/v1/audit-consumers/{behind_id}")).json()["consumer"]
            assert (
                ahead_view["last_acknowledged_checkpoint"]["checkpoint_id"] == second_id
            )
            assert (
                behind_view["last_acknowledged_checkpoint"]["checkpoint_id"] == first_id
            )


@pytest.mark.asyncio
async def test_unknown_consumer_and_unknown_checkpoint_use_not_found_envelope(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'consumers-404.db'}"
    checkpoints = await _sealed_database(database_url)
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    missing_consumer = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    missing_checkpoint = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            registered = await client.post(
                "/v1/audit-consumers",
                json={"consumer_name": "not-found-auditor", "idempotency_key": "nf-key"},
            )
            consumer_id = registered.json()["consumer"]["consumer_id"]

            unknown_consumer_ack = await client.post(
                f"/v1/audit-consumers/{missing_consumer}/acknowledgements",
                json={"checkpoint_id": checkpoints[0]["checkpoint_id"]},
            )
            unknown_consumer_get = await client.get(f"/v1/audit-consumers/{missing_consumer}")
            unknown_checkpoint = await client.post(
                f"/v1/audit-consumers/{consumer_id}/acknowledgements",
                json={"checkpoint_id": missing_checkpoint},
            )

    for response, entity, identifier in (
        (unknown_consumer_ack, "audit_consumer", missing_consumer),
        (unknown_consumer_get, "audit_consumer", missing_consumer),
        (unknown_checkpoint, "checkpoint", missing_checkpoint),
    ):
        assert response.status_code == 404
        body = response.json()["error"]
        assert body["code"] == "NOT_FOUND"
        assert body["details"]["entity"] == entity
        assert body["details"]["id"] == identifier
        assert body["request_id"]


@pytest.mark.asyncio
async def test_audit_consumer_database_failure_maps_to_503() -> None:
    broken_url = "sqlite+aiosqlite:////nonexistent-ledger-dir/consumers.db"
    app = _app(broken_url)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            registered = await client.post(
                "/v1/audit-consumers",
                json={"consumer_name": "db-down-auditor", "idempotency_key": "db-down-key"},
            )
            fetched = await client.get(
                "/v1/audit-consumers/cccccccc-cccc-cccc-cccc-cccccccccccc"
            )
            acknowledged = await client.post(
                "/v1/audit-consumers/cccccccc-cccc-cccc-cccc-cccccccccccc/acknowledgements",
                json={"checkpoint_id": "dddddddd-dddd-dddd-dddd-dddddddddddd"},
            )
    assert registered.status_code == 503
    assert fetched.status_code == 503
    assert acknowledged.status_code == 503
    for response in (registered, fetched, acknowledged):
        assert response.json()["error"]["code"] == "DATABASE_UNAVAILABLE"
