from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ledger.api.app import create_app
from ledger.config import Settings
from ledger.models import Base
from ledger.proofs import verify_receipt
from ledger.schemas import SubmitReport
from ledger.sealing import CheckpointSealer
from ledger.service import EventService
from tests.conftest import TEST_KEY_V1, TEST_KEY_V2

FIXED = datetime(2026, 5, 1, tzinfo=UTC)
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
                        business_key=f"incr-{sequence}",
                        instrument_id="CAL-INC",
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


def _app(database_url: str, *, keys: dict[str, str] | None = None, version: str = "v1"):
    return create_app(
        Settings(
            database_url=database_url,
            hmac_keys_json=json.dumps(keys or {"v1": KEY_TEXT}),
            current_key_version=version,
        )
    )


@pytest.mark.asyncio
async def test_first_checkpoint_increment_reads_the_full_prefix(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'incr-first.db'}"
    checkpoints = await _sealed_database(database_url)
    first = checkpoints[0]
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(f"/v1/checkpoints/{first['checkpoint_id']}/events")
    assert response.status_code == 200
    body = response.json()
    assert body["checkpoint_id"] == first["checkpoint_id"]
    assert body["has_more"] is False
    assert body["next_after_sequence"] is None
    items = body["items"]
    assert [item["event"]["sequence"] for item in items] == [1, 2, 3]
    for item in items:
        assert item["witness_status"] == "sealed"
        assert item["checkpoint"]["checkpoint_id"] == first["checkpoint_id"]
        assert item["consistency_proof"] is None
        # Every item is a standard receipt that verifies offline with the auditor keyring.
        assert verify_receipt(item, KEYRING) == {
            "valid": True,
            "witnessed": True,
            "checkpoint_id": first["checkpoint_id"],
        }


@pytest.mark.asyncio
async def test_increment_pages_are_disjoint_and_complete(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'incr-pages.db'}"
    checkpoints = await _sealed_database(database_url)
    first, second, third = checkpoints
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # An explicit cursor at the increment start equals the omitted-cursor first page.
            base = f"/v1/checkpoints/{second['checkpoint_id']}/events"
            implicit = await client.get(base, params={"limit": 2})
            explicit = await client.get(base, params={"after_sequence": 3, "limit": 2})
            assert implicit.status_code == 200
            assert implicit.json() == explicit.json()

            async def collect(checkpoint_id: str, limit: int) -> list[dict]:
                receipts: list[dict] = []
                cursor = None
                for _ in range(10):  # guards against a cursor that fails to advance
                    params: dict[str, object] = {"limit": limit}
                    if cursor is not None:
                        params["after_sequence"] = cursor
                    page = await client.get(
                        f"/v1/checkpoints/{checkpoint_id}/events", params=params
                    )
                    assert page.status_code == 200
                    body = page.json()
                    receipts.extend(body["items"])
                    if not body["has_more"]:
                        assert body["next_after_sequence"] is None
                        return receipts
                    cursor = body["next_after_sequence"]
                    assert isinstance(cursor, int)
                raise AssertionError("pagination did not terminate")

            second_receipts = await collect(str(second["checkpoint_id"]), 2)
            third_receipts = await collect(str(third["checkpoint_id"]), 1)

    # Only the newly covered events appear, in order, with no duplicates or gaps.
    assert [item["event"]["sequence"] for item in second_receipts] == [4, 5, 6, 7]
    assert [item["event"]["sequence"] for item in third_receipts] == [8, 9]
    for item in second_receipts:
        assert item["checkpoint"]["checkpoint_id"] == second["checkpoint_id"]
        assert item["consistency_proof"]["old_checkpoint"]["checkpoint_id"] == (
            first["checkpoint_id"]
        )
        assert verify_receipt(item, KEYRING)["valid"] is True
    for item in third_receipts:
        assert item["checkpoint"]["checkpoint_id"] == third["checkpoint_id"]
        assert item["consistency_proof"]["old_checkpoint"]["checkpoint_id"] == (
            second["checkpoint_id"]
        )
        assert verify_receipt(item, KEYRING)["valid"] is True


@pytest.mark.asyncio
async def test_pages_are_stable_after_later_events_and_checkpoints(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'incr-stable.db'}"
    checkpoints = await _sealed_database(database_url)
    second = checkpoints[1]
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        factory = app.state.session_factory
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            params = {"limit": 2}
            before = await client.get(
                f"/v1/checkpoints/{second['checkpoint_id']}/events", params=params
            )
            assert before.status_code == 200

            # Later events and a new checkpoint sealed under a rotated key must not move
            # the fixed boundary of an already sealed checkpoint.
            service = EventService(clock=lambda: FIXED)
            async with factory() as session:
                await service.append_report(
                    session,
                    SubmitReport(
                        business_key="incr-later-1",
                        instrument_id="CAL-INC",
                        operator_id="bob",
                        report={"reading": 99},
                    ),
                )
                await service.append_report(
                    session,
                    SubmitReport(
                        business_key="incr-later-2",
                        instrument_id="CAL-INC",
                        operator_id="bob",
                        report={"reading": 100},
                    ),
                )
            rotated = CheckpointSealer(
                keyring={"v1": TEST_KEY_V1, "v2": TEST_KEY_V2},
                current_key_version="v2",
                batch_size=100,
                clock=lambda: FIXED,
            )
            async with factory() as session:
                result = await rotated.seal_once(session)
            assert result.status == "sealed"

            after = await client.get(
                f"/v1/checkpoints/{second['checkpoint_id']}/events", params=params
            )
    assert after.status_code == 200
    assert after.content == before.content


@pytest.mark.asyncio
async def test_invalid_cursor_and_limit_get_clear_parameter_errors(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'incr-cursor.db'}"
    checkpoints = await _sealed_database(database_url)
    second = checkpoints[1]  # increment covers sequences 4-7
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            base = f"/v1/checkpoints/{second['checkpoint_id']}/events"
            before_start = await client.get(base, params={"after_sequence": 2})
            beyond_bound = await client.get(base, params={"after_sequence": 8})
            negative = await client.get(base, params={"after_sequence": -1})
            zero_limit = await client.get(base, params={"limit": 0})
            oversized_limit = await client.get(base, params={"limit": 501})

    for response in (before_start, beyond_bound):
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "INVALID_CURSOR"
        assert error["details"]["checkpoint_id"] == second["checkpoint_id"]
        assert error["details"]["increment_start"] == 3
        assert error["details"]["upper_bound"] == 7
        assert error["request_id"]
    assert before_start.json()["error"]["details"]["after_sequence"] == 2
    assert beyond_bound.json()["error"]["details"]["after_sequence"] == 8

    for response in (negative, zero_limit, oversized_limit):
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "INVALID_REQUEST"
        assert error["details"]["violations"]
        assert error["request_id"]


@pytest.mark.asyncio
async def test_non_integer_and_whitespace_padded_parameters_are_rejected(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'incr-format.db'}"
    checkpoints = await _sealed_database(database_url)
    second = checkpoints[1]  # increment covers sequences 4-7
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            base = f"/v1/checkpoints/{second['checkpoint_id']}/events"
            # Decimal points and surrounding whitespace must not be silently repaired
            # into an integer page parameter.
            malformed = [
                ({"limit": "2.0"}, "limit"),
                ({"limit": "2.5"}, "limit"),
                ({"after_sequence": "3.0"}, "after_sequence"),
                ({"after_sequence": "3.5"}, "after_sequence"),
                ({"limit": " 2 "}, "limit"),
                ({"limit": " 2"}, "limit"),
                ({"limit": "2 "}, "limit"),
                ({"after_sequence": " 3 "}, "after_sequence"),
                ({"after_sequence": " 3"}, "after_sequence"),
                ({"after_sequence": "3 "}, "after_sequence"),
            ]
            responses = [
                (await client.get(base, params=params), field) for params, field in malformed
            ]
            well_formed = await client.get(base, params={"after_sequence": "3", "limit": "2"})

    for response, field in responses:
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "INVALID_REQUEST"
        assert error["request_id"]
        locations = [violation["location"] for violation in error["details"]["violations"]]
        assert ["query", field] in locations

    # The same values as plain integer literals keep paginating normally.
    assert well_formed.status_code == 200
    body = well_formed.json()
    assert [item["event"]["sequence"] for item in body["items"]] == [4, 5]
    assert body["has_more"] is True
    assert body["next_after_sequence"] == 5


@pytest.mark.asyncio
async def test_page_at_upper_bound_is_empty_without_fabricated_cursor(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'incr-empty.db'}"
    checkpoints = await _sealed_database(database_url)
    second = checkpoints[1]
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                f"/v1/checkpoints/{second['checkpoint_id']}/events",
                params={"after_sequence": second["last_event_sequence"]},
            )
    assert response.status_code == 200
    body = response.json()
    assert body["items"] == []
    assert body["has_more"] is False
    assert body["next_after_sequence"] is None


@pytest.mark.asyncio
async def test_unknown_checkpoint_missing_key_and_database_failure(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'incr-errors.db'}"
    checkpoints = await _sealed_database(database_url)
    first = checkpoints[0]

    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    missing_id = "55555555-5555-5555-5555-555555555555"
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            missing = await client.get(f"/v1/checkpoints/{missing_id}/events")
    assert missing.status_code == 404
    error = missing.json()["error"]
    assert error["code"] == "NOT_FOUND"
    assert error["details"]["entity"] == "checkpoint"
    assert error["details"]["id"] == missing_id
    assert error["request_id"]

    # A keyring without the checkpoint's signing version keeps the existing 500 envelope.
    keyless = _app(database_url, keys={"v2": TEST_KEY_V2.decode()}, version="v2")
    keyless_transport = httpx.ASGITransport(app=keyless)
    async with keyless.router.lifespan_context(keyless):
        async with httpx.AsyncClient(
            transport=keyless_transport, base_url="http://test"
        ) as client:
            unknown_key = await client.get(f"/v1/checkpoints/{first['checkpoint_id']}/events")
    assert unknown_key.status_code == 500
    assert unknown_key.json()["error"]["code"] == "UNKNOWN_KEY_VERSION"
    assert unknown_key.json()["error"]["details"]["key_version"] == "v1"

    # A database outage maps to the standard retryable 503 envelope.
    broken = _app("sqlite+aiosqlite:////nonexistent-ledger-dir/incr.db")
    broken_transport = httpx.ASGITransport(app=broken, raise_app_exceptions=False)
    async with broken.router.lifespan_context(broken):
        async with httpx.AsyncClient(
            transport=broken_transport, base_url="http://test"
        ) as client:
            down = await client.get(f"/v1/checkpoints/{first['checkpoint_id']}/events")
    assert down.status_code == 503
    assert down.json()["error"]["code"] == "DATABASE_UNAVAILABLE"
    assert down.json()["error"]["details"]["retryable"] is True
