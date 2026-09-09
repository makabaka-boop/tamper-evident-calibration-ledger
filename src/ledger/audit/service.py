from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from ledger.audit.archive import PackageBundle, ReceiptEntry, build_archive
from ledger.canonical import canonical_json, sha256_hex
from ledger.domain import checkpoint_view, utc_now
from ledger.errors import LedgerError, NotFoundError
from ledger.models import AuditPackage, AuditPackageArtifact, Checkpoint, Event
from ledger.proofs import build_receipt_at_checkpoint

# Status values exposed in the API and database check constraints.
PENDING = "pending"
BUILDING = "building"
READY = "ready"
FAILED = "failed"
MAX_FAILURE_REASON = 2000


class AuditPackageService:
    def __init__(
        self,
        clock: Callable[[], datetime] = utc_now,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
    ) -> None:
        self.clock = clock
        self.uuid_factory = uuid_factory

    @staticmethod
    def _fingerprint(instrument_id: str, checkpoint_id: uuid.UUID) -> str:
        return sha256_hex(
            canonical_json(
                {
                    "instrument_id": instrument_id,
                    "checkpoint_id": str(checkpoint_id),
                }
            )
        )

    async def _resolve_boundary(
        self, session: AsyncSession, checkpoint_id: uuid.UUID | None
    ) -> Checkpoint:
        if checkpoint_id is not None:
            checkpoint = await session.get(Checkpoint, checkpoint_id)
            if not checkpoint:
                raise NotFoundError("checkpoint", str(checkpoint_id))
            return checkpoint
        checkpoint = await session.scalar(
            select(Checkpoint).order_by(Checkpoint.leaf_count.desc()).limit(1)
        )
        if not checkpoint:
            raise LedgerError(
                "NO_SEALED_CHECKPOINT",
                "no sealed checkpoint exists yet; create the package after sealing",
                409,
                {"retryable": True},
            )
        return checkpoint

    async def _boundary_event_count(
        self, session: AsyncSession, checkpoint: Checkpoint, instrument_id: str
    ) -> int:
        count = await session.scalar(
            select(func.count())
            .select_from(Event)
            .where(
                Event.instrument_id == instrument_id,
                Event.sequence <= checkpoint.last_event_sequence,
            )
        )
        return int(count or 0)

    @staticmethod
    def _boundary_mismatch(
        checkpoint: Checkpoint, instrument_id: str, *, explicit: bool
    ) -> LedgerError:
        if explicit:
            return LedgerError(
                "CHECKPOINT_DOES_NOT_COVER_INSTRUMENT",
                "the selected checkpoint boundary contains no event for the instrument",
                409,
                {
                    "checkpoint_id": str(checkpoint.checkpoint_id),
                    "instrument_id": instrument_id,
                    "retryable": False,
                },
            )
        return LedgerError(
            "INSTRUMENT_HAS_NO_SEALED_EVENTS",
            "the latest sealed boundary contains no event for the instrument",
            409,
            {
                "checkpoint_id": str(checkpoint.checkpoint_id),
                "instrument_id": instrument_id,
                "retryable": True,
            },
        )

    async def create_package(
        self,
        session: AsyncSession,
        *,
        instrument_id: str,
        idempotency_key: str,
        checkpoint_id: uuid.UUID | None = None,
    ) -> tuple[AuditPackage, bool]:
        try:
            async with session.begin():
                existing = await session.scalar(
                    select(AuditPackage).where(AuditPackage.idempotency_key == idempotency_key)
                )
                if existing:
                    self._raise_unless_replay(existing, instrument_id, checkpoint_id)
                    return existing, False

                checkpoint = await self._resolve_boundary(session, checkpoint_id)
                if await self._boundary_event_count(session, checkpoint, instrument_id) == 0:
                    raise self._boundary_mismatch(
                        checkpoint, instrument_id, explicit=checkpoint_id is not None
                    )

                now = self.clock()
                package = AuditPackage(
                    package_id=self.uuid_factory(),
                    idempotency_key=idempotency_key,
                    request_fingerprint=self._fingerprint(
                        instrument_id, checkpoint.checkpoint_id
                    ),
                    instrument_id=instrument_id,
                    checkpoint_id=checkpoint.checkpoint_id,
                    status=PENDING,
                    attempt_count=0,
                    created_at=now,
                    updated_at=now,
                )
                session.add(package)
                await session.flush()
                return package, True
        except IntegrityError:
            # Concurrent creators racing on the unique idempotency key: settle from the row.
            await session.rollback()
            existing = await session.scalar(
                select(AuditPackage).where(AuditPackage.idempotency_key == idempotency_key)
            )
            if existing:
                self._raise_unless_replay(existing, instrument_id, checkpoint_id)
                return existing, False
            raise

    @staticmethod
    def _raise_unless_replay(
        existing: AuditPackage, instrument_id: str, checkpoint_id: uuid.UUID | None
    ) -> None:
        if existing.instrument_id == instrument_id and (
            checkpoint_id is None or existing.checkpoint_id == checkpoint_id
        ):
            return
        raise LedgerError(
            "IDEMPOTENCY_CONFLICT",
            "idempotency key was already used with different parameters",
            409,
            {
                "idempotency_key": existing.idempotency_key,
                "package_id": str(existing.package_id),
                "instrument_id": existing.instrument_id,
                "checkpoint_id": str(existing.checkpoint_id),
            },
        )

    async def claim_package(
        self,
        session: AsyncSession,
        *,
        worker_id: str,
        lease_duration: timedelta,
        now: datetime | None = None,
    ) -> AuditPackage | None:
        """Atomically claim one pending or stale-building package.

        PostgreSQL uses FOR UPDATE SKIP LOCKED so concurrent workers never take the same
        task. SQLite serializes writers; a conditional UPDATE whose WHERE re-checks the
        status provides equivalent compare-and-set semantics.
        """

        moment = now or self.clock()
        dialect = session.bind.dialect.name if session.bind is not None else ""
        eligible = (AuditPackage.status == PENDING) | (
            (AuditPackage.status == BUILDING) & (AuditPackage.lease_expires_at < moment)
        )
        async with session.begin():
            if dialect == "postgresql":
                candidate = await session.scalar(
                    select(AuditPackage)
                    .where(eligible)
                    .order_by(AuditPackage.id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if not candidate:
                    return None
                candidate.status = BUILDING
                candidate.lease_owner = worker_id
                candidate.lease_expires_at = moment + lease_duration
                candidate.attempt_count += 1
                candidate.updated_at = moment
                await session.flush()
                return candidate

            candidate_id = await session.scalar(
                select(AuditPackage.id).where(eligible).order_by(AuditPackage.id).limit(1)
            )
            if candidate_id is None:
                return None
            result = await session.execute(
                update(AuditPackage)
                .where(
                    (AuditPackage.id == candidate_id)
                    & (
                        (AuditPackage.status == PENDING)
                        | (
                            (AuditPackage.status == BUILDING)
                            & (AuditPackage.lease_expires_at < moment)
                        )
                    )
                )
                .values(
                    status=BUILDING,
                    lease_owner=worker_id,
                    lease_expires_at=moment + lease_duration,
                    attempt_count=AuditPackage.attempt_count + 1,
                    updated_at=moment,
                )
            )
            if result.rowcount == 0:
                return None
            return await session.scalar(
                select(AuditPackage).where(AuditPackage.id == candidate_id)
            )

    async def _load_bundle(
        self,
        session: AsyncSession,
        package: AuditPackage,
        keyring: Mapping[str, bytes],
    ) -> PackageBundle:
        checkpoint = await session.get(Checkpoint, package.checkpoint_id)
        if not checkpoint:
            raise LedgerError(
                "CHECKPOINT_CHAIN_BROKEN",
                "fixed boundary checkpoint is missing",
                500,
                {"checkpoint_id": str(package.checkpoint_id)},
            )
        events = list(
            (
                await session.scalars(
                    select(Event)
                    .where(
                        Event.instrument_id == package.instrument_id,
                        Event.sequence <= checkpoint.last_event_sequence,
                    )
                    .order_by(Event.sequence)
                )
            ).all()
        )
        if not events:
            raise LedgerError(
                "AUDIT_BOUNDARY_EMPTY",
                "the fixed boundary contains no event for the instrument",
                500,
                {
                    "package_id": str(package.package_id),
                    "instrument_id": package.instrument_id,
                },
            )
        entries: list[ReceiptEntry] = []
        for event in events:
            receipt = await build_receipt_at_checkpoint(session, event, checkpoint, keyring)
            entries.append(ReceiptEntry(sequence=event.sequence, receipt=receipt))
        return PackageBundle(
            package_id=str(package.package_id),
            idempotency_key=package.idempotency_key,
            instrument_id=package.instrument_id,
            checkpoint=checkpoint_view(checkpoint),
            entries=tuple(entries),
        )

    async def build_once(self, session_factory, claimed: AuditPackage, keyring) -> str:
        """Build the archive for an already claimed package.

        Returns READY on success or FAILED after recording the cause. Database driver
        errors deliberately propagate: the lease then expires and another worker
        reclaims the crashed attempt without its attempt being marked terminal.
        """

        worker_id = claimed.lease_owner
        try:
            async with session_factory() as read_session:
                bundle = await self._load_bundle(read_session, claimed, keyring)
            archive = build_archive(bundle)
        except SQLAlchemyError:
            # Database outage: leave the lease to expire so a healthy worker reclaims.
            raise
        except LedgerError as exc:
            await self._mark_failed(session_factory, claimed, exc.code, exc.message)
            return FAILED
        except Exception as exc:  # packaging defects are recorded, not retried forever
            await self._mark_failed(
                session_factory, claimed, "AUDIT_EXPORT_FAILED", str(exc)[:MAX_FAILURE_REASON]
            )
            return FAILED

        async with session_factory() as write_session:
            async with write_session.begin():
                package = await write_session.get(
                    AuditPackage, claimed.id, with_for_update=True
                )
                if not package or package.status != BUILDING or package.lease_owner != worker_id:
                    # Lost the lease after a crash-timeout reclaim; discard produced bytes.
                    return package.status if package else FAILED
                now = self.clock()
                write_session.add(
                    AuditPackageArtifact(
                        package_id=package.package_id,
                        zip_content=archive.content,
                        sha256=archive.sha256,
                        size_bytes=archive.size_bytes,
                        created_at=now,
                    )
                )
                package.status = READY
                package.artifact_sha256 = archive.sha256
                package.artifact_size_bytes = archive.size_bytes
                package.event_count = archive.event_count
                package.lease_owner = None
                package.lease_expires_at = None
                package.ready_at = now
                package.updated_at = now
        return READY

    async def _mark_failed(
        self, session_factory, claimed: AuditPackage, code: str, reason: str
    ) -> None:
        async with session_factory() as fail_session:
            async with fail_session.begin():
                package = await fail_session.get(
                    AuditPackage, claimed.id, with_for_update=True
                )
                if (
                    not package
                    or package.status != BUILDING
                    or package.lease_owner != claimed.lease_owner
                ):
                    return
                now = self.clock()
                package.status = FAILED
                package.failure_code = code
                package.failure_reason = reason[:MAX_FAILURE_REASON]
                package.lease_owner = None
                package.lease_expires_at = None
                package.failed_at = now
                package.updated_at = now

    async def request_retry(self, session: AsyncSession, package_id: uuid.UUID) -> AuditPackage:
        async with session.begin():
            package = await session.scalar(
                select(AuditPackage)
                .where(AuditPackage.package_id == package_id)
                .with_for_update()
            )
            if not package:
                raise NotFoundError("audit_package", str(package_id))
            if package.status == FAILED:
                now = self.clock()
                package.status = PENDING
                package.failure_code = None
                package.failure_reason = None
                package.failed_at = None
                package.lease_owner = None
                package.lease_expires_at = None
                package.updated_at = now
                # checkpoint_id / instrument_id / request_fingerprint stay fixed forever.
                return package
            if package.status == PENDING:
                raise LedgerError(
                    "AUDIT_PACKAGE_NOT_FAILED",
                    "the package is already queued for export",
                    409,
                    {"package_id": str(package_id), "status": PENDING},
                )
            if package.status == BUILDING:
                raise LedgerError(
                    "AUDIT_PACKAGE_BUILDING",
                    "the package is currently being built; retry after it settles",
                    409,
                    {"package_id": str(package_id), "status": BUILDING},
                )
            raise LedgerError(
                "AUDIT_PACKAGE_ALREADY_READY",
                "a ready package cannot be retried",
                409,
                {"package_id": str(package_id), "status": READY},
            )

    async def get_package(self, session: AsyncSession, package_id: uuid.UUID) -> AuditPackage:
        package = await session.scalar(
            select(AuditPackage).where(AuditPackage.package_id == package_id)
        )
        if not package:
            raise NotFoundError("audit_package", str(package_id))
        return package

    async def get_ready_artifact(
        self, session: AsyncSession, package_id: uuid.UUID
    ) -> tuple[AuditPackage, AuditPackageArtifact]:
        package = await self.get_package(session, package_id)
        if package.status != READY:
            raise LedgerError(
                "AUDIT_PACKAGE_NOT_READY",
                f"the package is {package.status}; the download is available when ready",
                409,
                {
                    "package_id": str(package_id),
                    "status": package.status,
                    "retryable": package.status == FAILED,
                },
            )
        artifact = await session.get(AuditPackageArtifact, package.package_id)
        if not artifact:
            raise LedgerError(
                "AUDIT_ARTIFACT_MISSING",
                "the package is marked ready but its archive is absent",
                500,
                {"package_id": str(package_id)},
            )
        return package, artifact
