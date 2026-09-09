from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from ledger.api.app import create_app
from ledger.config import Settings
from ledger.models import Base
from tests.conftest import TEST_KEY_V1


@pytest.mark.asyncio
async def test_api_returns_idempotent_result_and_structured_conflict(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'api.db'}"
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
    payload = {
        "business_key": "api-request-1",
        "instrument_id": "INST-HTTP",
        "operator_id": "alice",
        "report": {"reading": 4.2},
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            created = await client.post("/v1/reports", json=payload)
            repeated = await client.post("/v1/reports", json=payload)
            conflict = await client.post(
                "/v1/reports", json={**payload, "report": {"reading": 4.3}}
            )
    assert created.status_code == 201
    assert repeated.status_code == 200
    assert repeated.json()["event"]["event_id"] == created.json()["event"]["event_id"]
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    assert conflict.json()["error"]["request_id"]


@pytest.mark.asyncio
async def test_api_validation_errors_have_stable_shape(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'invalid.db'}"
    engine = create_async_engine(database_url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    await engine.dispose()
    app = create_app(
        Settings(
            database_url=database_url,
            hmac_keys_json=json.dumps({"v1": TEST_KEY_V1.decode()}),
        )
    )
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/v1/reports", json={"business_key": "missing-fields"})
    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "INVALID_REQUEST"
    assert body["request_id"]
    assert body["details"]["violations"]
