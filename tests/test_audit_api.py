from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ledger.api.app import create_app
from ledger.audit.service import AuditPackageService
from ledger.config import Settings
from ledger.domain import audit_package_view
from ledger.models import Base
from ledger.proofs import verify_receipt
from ledger.schemas import SubmitReport
from ledger.sealing import CheckpointSealer
from ledger.service import EventService
from tests.conftest import TEST_KEY_V1

FIXED = datetime(2026, 3, 1, tzinfo=UTC)
KEY_TEXT = TEST_KEY_V1.decode()
KEYRING = {"v1": TEST_KEY_V1}


async def _prepared_database(database_url: str, *, other_instrument: bool = False) -> str:
    engine = create_async_engine(database_url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    service = EventService(clock=lambda: FIXED)
    async with factory() as session:
        await service.append_report(
            session,
            SubmitReport(
                business_key="http-report-1",
                instrument_id="CAL-HTTP",
                operator_id="alice",
                report={"reading": 1.5},
            ),
        )
        await service.append_report(
            session,
            SubmitReport(
                business_key="http-report-2",
                instrument_id="CAL-HTTP",
                operator_id="bob",
                report={"reading": 1.6},
            ),
        )
    if other_instrument:
        async with factory() as session:
            await service.append_report(
                session,
                SubmitReport(
                    business_key="http-other",
                    instrument_id="CAL-ELSE",
                    operator_id="carol",
                    report={"reading": 9.0},
                ),
            )
    sealer = CheckpointSealer(
        keyring=KEYRING, current_key_version="v1", batch_size=100, clock=lambda: FIXED
    )
    async with factory() as session:
        await sealer.seal_once(session)
    await engine.dispose()
    return database_url


def _app(database_url: str) -> object:
    return create_app(
        Settings(
            database_url=database_url,
            hmac_keys_json=json.dumps({"v1": KEY_TEXT}),
            current_key_version="v1",
        )
    )


async def _build_package(factory, package_id: str) -> None:
    """Drive one worker claim/build cycle directly against a session factory."""

    from datetime import timedelta

    service = AuditPackageService(clock=lambda: FIXED)
    async with factory() as session:
        claimed = await service.claim_package(
            session, worker_id="test-worker", lease_duration=timedelta(minutes=5)
        )
    assert claimed is not None and str(claimed.package_id) == package_id
    status = await service.build_once(factory, claimed, KEYRING)
    assert status == "ready"


@pytest.mark.asyncio
async def test_audit_package_create_status_download_lifecycle(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'audit-api.db'}"
    await _prepared_database(database_url)
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        factory = app.state.session_factory
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            created = await client.post(
                "/v1/audit-packages",
                json={"instrument_id": "CAL-HTTP", "idempotency_key": "api-key-1"},
            )
            assert created.status_code == 201
            package = created.json()["package"]
            assert package["status"] == "pending"
            assert package["attempt_count"] == 0
            assert package["artifact"] is None
            assert package["failure"] is None
            package_id = package["package_id"]

            status = await client.get(f"/v1/audit-packages/{package_id}")
            assert status.status_code == 200
            assert status.json()["package"]["package_id"] == package_id

            # Download before completion is a clear conflict, not 404 or a stream.
            early_download = await client.get(f"/v1/audit-packages/{package_id}/download")
            assert early_download.status_code == 409
            error = early_download.json()["error"]
            assert error["code"] == "AUDIT_PACKAGE_NOT_READY"
            assert error["details"]["status"] == "pending"
            assert error["request_id"]

            await _build_package(factory, package_id)

            ready = await client.get(f"/v1/audit-packages/{package_id}")
            assert ready.status_code == 200
            ready_body = ready.json()["package"]
            assert ready_body["status"] == "ready"
            assert ready_body["event_count"] == 2
            assert ready_body["artifact"]["sha256"]
            assert ready_body["artifact"]["size_bytes"] > 0

            download = await client.get(f"/v1/audit-packages/{package_id}/download")
            assert download.status_code == 200
            assert download.headers["content-type"] == "application/zip"
            assert "attachment" in download.headers["content-disposition"]
            assert download.headers["x-content-sha-256"] == ready_body["artifact"]["sha256"]
            data = download.content
            import hashlib

            assert hashlib.sha256(data).hexdigest() == ready_body["artifact"]["sha256"]

            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                receipt_names = [
                    name
                    for name in archive.namelist()
                    if name.startswith("receipts/") and name.endswith(".json")
                ]
                assert len(receipt_names) == 2
                for name in receipt_names:
                    receipt = json.loads(archive.read(name))
                    assert verify_receipt(receipt, KEYRING)["valid"] is True
            assert manifest["instrument_id"] == "CAL-HTTP"
            assert manifest["event_count"] == 2
            # No raw report content and no HMAC material ship in the package: the receipts
            # expose the report digest, and the bytes are DEFLATE-compressed anyway.
            assert TEST_KEY_V1 not in data
            with zipfile.ZipFile(io.BytesIO(data)) as re_opened:
                decompressed = b"".join(
                    re_opened.read(name) for name in re_opened.namelist()
                )
            # Only the report digest appears; the submitted report payload is absent.
            assert b'"report":{' not in decompressed
            assert b"reading" not in decompressed
            assert b"1.5" not in decompressed


@pytest.mark.asyncio
async def test_audit_package_idempotency_replay_and_conflict(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'audit-idempotent.db'}"
    await _prepared_database(database_url, other_instrument=True)
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    payload = {"instrument_id": "CAL-HTTP", "idempotency_key": "idem-http"}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            first = await client.post("/v1/audit-packages", json=payload)
            second = await client.post("/v1/audit-packages", json=payload)
            conflict = await client.post(
                "/v1/audit-packages",
                json={"instrument_id": "CAL-ELSE", "idempotency_key": "idem-http"},
            )
    assert first.status_code == 201
    assert second.status_code == 200
    assert second.json()["created"] is False
    assert (
        second.json()["package"]["package_id"] == first.json()["package"]["package_id"]
    )
    assert conflict.status_code == 409
    body = conflict.json()["error"]
    assert body["code"] == "IDEMPOTENCY_CONFLICT"
    assert body["details"]["idempotency_key"] == "idem-http"
    assert body["request_id"]


@pytest.mark.asyncio
async def test_audit_package_boundary_errors_are_structured(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'audit-boundary.db'}"
    await _prepared_database(database_url)
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            missing = await client.post(
                "/v1/audit-packages",
                json={"instrument_id": "NEVER-SEALED", "idempotency_key": "miss-1"},
            )
            assert missing.status_code == 409
            assert missing.json()["error"]["code"] == "INSTRUMENT_HAS_NO_SEALED_EVENTS"

            explicit = await client.post(
                "/v1/audit-packages",
                json={
                    "instrument_id": "NEVER-SEALED",
                    "idempotency_key": "miss-2",
                    "checkpoint_id": "00000000-0000-0000-0000-000000000000",
                },
            )
            assert explicit.status_code == 404
            assert explicit.json()["error"]["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_audit_package_failure_retry_and_download_conflict(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'audit-retry.db'}"
    await _prepared_database(database_url)
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    from datetime import timedelta

    service = AuditPackageService(clock=lambda: FIXED)
    async with app.router.lifespan_context(app):
        factory = app.state.session_factory
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            created = await client.post(
                "/v1/audit-packages",
                json={"instrument_id": "CAL-HTTP", "idempotency_key": "retry-http"},
            )
            package_id = created.json()["package"]["package_id"]

            # Force a deterministic failure using a keyring missing the signing version.
            async with factory() as session:
                claimed = await service.claim_package(
                    session, worker_id="bad", lease_duration=timedelta(minutes=5)
                )
            assert await service.build_once(factory, claimed, {"v9": TEST_KEY_V1}) == "failed"

            failed_view = await client.get(f"/v1/audit-packages/{package_id}")
            assert failed_view.json()["package"]["status"] == "failed"
            assert failed_view.json()["package"]["failure"]["code"] == "UNKNOWN_KEY_VERSION"

            blocked = await client.get(f"/v1/audit-packages/{package_id}/download")
            assert blocked.status_code == 409
            assert blocked.json()["error"]["details"]["retryable"] is True

            retried = await client.post(f"/v1/audit-packages/{package_id}/retry")
            assert retried.status_code == 200
            assert retried.json()["package"]["status"] == "pending"
            assert retried.json()["package"]["failure"] is None
            boundary_before = created.json()["package"]["checkpoint_id"]
            assert retried.json()["package"]["checkpoint_id"] == boundary_before

            await _build_package(factory, package_id)
            download = await client.get(f"/v1/audit-packages/{package_id}/download")
            assert download.status_code == 200

            retry_ready = await client.post(f"/v1/audit-packages/{package_id}/retry")
            assert retry_ready.status_code == 409
            assert retry_ready.json()["error"]["code"] == "AUDIT_PACKAGE_ALREADY_READY"


@pytest.mark.asyncio
async def test_unknown_audit_package_uses_existing_error_envelope(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'audit-404.db'}"
    await _prepared_database(database_url)
    app = _app(database_url)
    transport = httpx.ASGITransport(app=app)
    missing_id = "11111111-1111-1111-1111-111111111111"
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            status = await client.get(f"/v1/audit-packages/{missing_id}")
            download = await client.get(f"/v1/audit-packages/{missing_id}/download")
            retry = await client.post(f"/v1/audit-packages/{missing_id}/retry")
    for response, code in (
        (status, 404),
        (download, 404),
        (retry, 404),
    ):
        assert response.status_code == code
        body = response.json()["error"]
        assert body["code"] == "NOT_FOUND"
        assert body["details"]["entity"] == "audit_package"
        assert body["details"]["id"] == missing_id
        assert body["request_id"]


@pytest.mark.asyncio
async def test_database_failure_maps_to_503_for_audit_endpoints() -> None:
    broken_url = "sqlite+aiosqlite:////nonexistent-ledger-dir/audit.db"
    app = _app(broken_url)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            created = await client.post(
                "/v1/audit-packages",
                json={"instrument_id": "CAL-HTTP", "idempotency_key": "db-down"},
            )
            fetched = await client.get(
                "/v1/audit-packages/22222222-2222-2222-2222-222222222222"
            )
            downloaded = await client.get(
                "/v1/audit-packages/22222222-2222-2222-2222-222222222222/download"
            )
    assert created.status_code == 503
    assert created.json()["error"]["code"] == "DATABASE_UNAVAILABLE"
    assert fetched.status_code == 503
    assert downloaded.status_code == 503


@pytest.mark.asyncio
async def test_audit_package_view_reports_attempt_count_and_summary(tmp_path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'audit-view.db'}"
    await _prepared_database(database_url)
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    service = AuditPackageService(clock=lambda: FIXED)
    from datetime import timedelta

    async with factory() as session:
        package, _ = await service.create_package(
            session, instrument_id="CAL-HTTP", idempotency_key="view-1"
        )
        claimed = await service.claim_package(
            session, worker_id="w", lease_duration=timedelta(minutes=5)
        )
    await service.build_once(factory, claimed, KEYRING)
    async with factory() as session:
        ready = await service.get_package(session, package.package_id)
        view = audit_package_view(ready)
    assert view["package_id"] == str(package.package_id)
    assert view["status"] == "ready"
    assert view["attempt_count"] == 1
    assert view["artifact"]["event_count"] == 2
    assert len(view["boundary"]["request_fingerprint"]) == 64
    assert view["boundary"]["request_fingerprint"] == package.request_fingerprint
    await engine.dispose()
