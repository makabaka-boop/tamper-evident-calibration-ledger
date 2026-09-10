from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ledger.audit.consumers import AuditConsumerService
from ledger.audit.service import CANCELLED, AuditPackageService
from tests.conftest import TEST_KEY_V1

pytestmark = pytest.mark.postgres

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def postgres_url() -> str:
    value = os.getenv("TEST_DATABASE_URL")
    if not value or not value.startswith("postgresql+asyncpg://"):
        pytest.skip("set TEST_DATABASE_URL to an isolated PostgreSQL database")
    return value


def _alembic(postgres_url: str, *arguments: str) -> str:
    env = {
        **os.environ,
        "LEDGER_DATABASE_URL": postgres_url,
        "LEDGER_HMAC_KEYS_JSON": json.dumps({"v1": TEST_KEY_V1.decode()}),
        "LEDGER_CURRENT_KEY_VERSION": "v1",
        "PYTHONPATH": str(ROOT / "src"),
    }
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.mark.asyncio
async def test_0003_preserves_legacy_tasks_and_extends_lifecycle(postgres_url) -> None:
    engine = create_async_engine(postgres_url, pool_size=4)
    async with engine.begin() as connection:
        await connection.execute(text("DROP TABLE IF EXISTS audit_package_artifacts"))
        await connection.execute(text("DROP TABLE IF EXISTS audit_packages"))
        await connection.execute(text("DROP TABLE IF EXISTS checkpoints"))
        await connection.execute(text("DROP TABLE IF EXISTS events"))
        await connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
        await connection.execute(
            text("DROP FUNCTION IF EXISTS audit_package_reject_identity_mutation()")
        )
        await connection.execute(text("DROP FUNCTION IF EXISTS ledger_reject_mutation()"))

    # Build the pre-cancellation schema from scratch, one revision at a time.
    _alembic(postgres_url, "upgrade", "0001_append_only_ledger")
    _alembic(postgres_url, "upgrade", "0002_audit_packages")

    now = datetime(2026, 6, 1, tzinfo=UTC)
    event_id = uuid.uuid4()
    checkpoint_id = uuid.uuid4()
    package_ids = {status: uuid.uuid4() for status in ("pending", "building", "ready", "failed")}

    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO events (sequence, event_id, record_id, event_type, business_key, "
                "content_fingerprint, instrument_id, operator_id, report_digest, "
                "reason, occurred_at, leaf_hash) VALUES (1, :event_id, :event_id, 'report', "
                "'legacy-bk', :fingerprint, 'LEGACY-1', 'alice', :digest, NULL, :now, "
                ":leaf)"
            ),
            {
                "event_id": event_id,
                "now": now,
                "fingerprint": "a" * 64,
                "digest": "b" * 64,
                "leaf": "c" * 64,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO checkpoints (checkpoint_id, leaf_count, last_event_sequence, "
                "root_hash, previous_checkpoint_id, previous_root_hash, key_version, "
                "created_at, signature) VALUES (:cid, 1, 1, :root, NULL, NULL, 'v1', "
                ":now, :signature)"
            ),
            {"cid": checkpoint_id, "now": now, "root": "d" * 64, "signature": "e" * 64},
        )

        async def insert_package(status: str, **overrides) -> None:
            values = {
                "package_id": package_ids[status],
                "idempotency_key": f"legacy-{status}",
                "request_fingerprint": "f" * 64,
                "instrument_id": "LEGACY-1",
                "checkpoint_id": checkpoint_id,
                "status": status,
                "attempt_count": 1,
                "lease_owner": None,
                "lease_expires_at": None,
                "failure_code": None,
                "failure_reason": None,
                "artifact_sha256": None,
                "artifact_size_bytes": None,
                "event_count": None,
                "created_at": now,
                "updated_at": now,
                "ready_at": None,
                "failed_at": None,
                **overrides,
            }
            await connection.execute(
                text(
                    "INSERT INTO audit_packages (package_id, idempotency_key, "
                    "request_fingerprint, instrument_id, checkpoint_id, status, attempt_count, "
                    "lease_owner, lease_expires_at, failure_code, failure_reason, "
                    "artifact_sha256, artifact_size_bytes, event_count, created_at, updated_at, "
                    "ready_at, failed_at) VALUES (:package_id, :idempotency_key, "
                    ":request_fingerprint, :instrument_id, :checkpoint_id, :status, "
                    ":attempt_count, :lease_owner, :lease_expires_at, :failure_code, "
                    ":failure_reason, :artifact_sha256, :artifact_size_bytes, :event_count, "
                    ":created_at, :updated_at, :ready_at, :failed_at)"
                ),
                values,
            )

        await insert_package("pending", attempt_count=0)
        await insert_package(
            "building",
            lease_owner="dead-worker",
            lease_expires_at=now + timedelta(minutes=5),
        )
        await insert_package(
            "ready",
            attempt_count=2,
            artifact_sha256="1" * 64,
            artifact_size_bytes=42,
            event_count=1,
            ready_at=now,
        )
        await connection.execute(
            text(
                "INSERT INTO audit_package_artifacts (package_id, zip_content, sha256, "
                "size_bytes, created_at) VALUES (:pid, :content, :sha, 42, :now)"
            ),
            {
                "pid": package_ids["ready"],
                "content": b"PK\x03\x04-legacy",
                "sha": "1" * 64,
                "now": now,
            },
        )
        await insert_package(
            "failed",
            failure_code="UNKNOWN_KEY_VERSION",
            failure_reason="unknown signing key version: v9",
            failed_at=now,
        )

    # Apply the cancellation migration; every legacy task must survive it untouched.
    _alembic(postgres_url, "upgrade", "0003_audit_package_cancellation")
    current = _alembic(postgres_url, "current")
    assert "0003_audit_package_cancellation" in current

    async with engine.begin() as connection:
        rows = list(
            await connection.execute(
                text(
                    "SELECT package_id, status, attempt_count, cancel_requested_at, "
                    "cancelled_at FROM audit_packages ORDER BY status"
                )
            )
        )
    by_status = {row.status: row for row in rows}
    assert set(by_status) == {"pending", "building", "ready", "failed"}
    assert all(row.cancel_requested_at is None for row in rows)
    assert all(row.cancelled_at is None for row in rows)
    assert by_status["ready"].attempt_count == 2

    # The extended state constraint now governs cancellation on the migrated database.
    factory = async_sessionmaker(engine, expire_on_commit=False)
    service = AuditPackageService(clock=lambda: now + timedelta(minutes=1))
    async with factory() as session:
        cancelled, changed = await service.cancel_package(session, package_ids["pending"])
    assert changed is True
    assert cancelled.status == CANCELLED

    async with engine.begin() as connection:
        migrated = await connection.execute(
            text(
                "SELECT status, cancel_requested_at, cancelled_at FROM audit_packages "
                "WHERE package_id = :pid"
            ),
            {"pid": package_ids["pending"]},
        )
        status, requested_at, cancelled_at = migrated.one()
    assert status == "cancelled"
    assert requested_at is not None and cancelled_at is not None

    # Downgrading with no cancellation-state rows restores the legacy constraint.
    _alembic(postgres_url, "downgrade", "0002_audit_packages")
    async with engine.begin() as connection:
        version = await connection.scalar(text("SELECT version_num FROM alembic_version"))
        columns = {
            row.column_name
            for row in await connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'audit_packages'"
                )
            )
        }
    assert version == "0002_audit_packages"
    assert "cancel_requested_at" not in columns
    assert "cancelled_at" not in columns
    await engine.dispose()


@pytest.mark.asyncio
async def test_0004_adds_audit_consumers_and_removes_them_on_downgrade(postgres_url) -> None:
    engine = create_async_engine(postgres_url, pool_size=4)
    # Start from a clean database and migrate straight to head.
    async with engine.begin() as connection:
        await connection.execute(text("DROP TABLE IF EXISTS audit_package_artifacts"))
        await connection.execute(text("DROP TABLE IF EXISTS audit_packages"))
        await connection.execute(text("DROP TABLE IF EXISTS audit_consumers"))
        await connection.execute(text("DROP TABLE IF EXISTS checkpoints"))
        await connection.execute(text("DROP TABLE IF EXISTS events"))
        await connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
        await connection.execute(
            text("DROP FUNCTION IF EXISTS audit_consumer_reject_identity_mutation()")
        )
        await connection.execute(
            text("DROP FUNCTION IF EXISTS audit_package_reject_identity_mutation()")
        )
        await connection.execute(text("DROP FUNCTION IF EXISTS ledger_reject_mutation()"))

    _alembic(postgres_url, "upgrade", "head")
    assert "0004_audit_consumers" in _alembic(postgres_url, "current")

    def inspect_table(sync_connection):
        inspector = inspect(sync_connection)
        columns = {column["name"] for column in inspector.get_columns("audit_consumers")}
        unique = {
            constraint["name"]
            for constraint in inspector.get_unique_constraints("audit_consumers")
        }
        foreign_keys = {
            constraint["referred_table"]
            for constraint in inspector.get_foreign_keys("audit_consumers")
        }
        indexes = {index["name"] for index in inspector.get_indexes("audit_consumers")}
        return columns, unique, foreign_keys, indexes

    async with engine.begin() as connection:
        columns, unique, foreign_keys, indexes = await connection.run_sync(inspect_table)
    assert columns == {
        "id",
        "consumer_id",
        "consumer_name",
        "idempotency_key",
        "last_checkpoint_id",
        "created_at",
        "updated_at",
        "last_acknowledged_at",
    }
    assert unique == {"uq_audit_consumers_consumer_id", "uq_audit_consumers_idempotency_key"}
    assert foreign_keys == {"checkpoints"}
    assert "ix_audit_consumers_name" in indexes

    # The service contract works end to end against the migration-built schema.
    factory = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime(2026, 8, 1, tzinfo=UTC)
    service = AuditConsumerService(clock=lambda: now)
    async with factory() as session:
        consumer, created = await service.register_consumer(
            session, consumer_name="migrated-auditor", idempotency_key="migration-key"
        )
    assert created is True
    async with factory() as session:
        replay_consumer, replay_created = await service.register_consumer(
            session, consumer_name="migrated-auditor", idempotency_key="migration-key"
        )
    assert replay_created is False
    assert replay_consumer.consumer_id == consumer.consumer_id

    # The fixed identity trigger forbids rewriting the registration identity.
    async with engine.begin() as connection:
        with pytest.raises(IntegrityError):
            await connection.execute(
                text(
                    "UPDATE audit_consumers SET consumer_name = :name "
                    "WHERE consumer_id = :cid"
                ),
                {"name": "tampered", "cid": consumer.consumer_id},
            )

    # Downgrading drops the table and its trigger/function while leaving prior revisions intact.
    _alembic(postgres_url, "downgrade", "0003_audit_package_cancellation")
    assert (
        _alembic(postgres_url, "current").strip() == "0003_audit_package_cancellation"
    )

    async with engine.begin() as connection:
        table_names = await connection.run_sync(
            lambda sync_connection: inspect(sync_connection).get_table_names()
        )
    assert "audit_consumers" not in table_names
    await engine.dispose()
