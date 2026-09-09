from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ledger.coordination import SEALER_ADVISORY_LOCK_ID
from ledger.domain import checkpoint_signing_bytes, event_commitment_bytes, utc_now
from ledger.errors import LedgerError
from ledger.merkle import leaf_hash, merkle_root
from ledger.models import Checkpoint, Event
from ledger.security import (
    KeyConfigurationError,
    require_key,
    sign_checkpoint,
    verify_checkpoint_signature,
)


@dataclass(frozen=True)
class SealResult:
    status: str
    checkpoint: Checkpoint | None = None


class CheckpointSealer:
    def __init__(
        self,
        *,
        keyring: Mapping[str, bytes],
        current_key_version: str,
        batch_size: int,
        clock: Callable[[], datetime] = utc_now,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch size must be positive")
        self.keyring = keyring
        self.current_key_version = current_key_version
        self.batch_size = batch_size
        self.clock = clock
        self.uuid_factory = uuid_factory

    def _signing_key(self, version: str) -> bytes:
        try:
            return require_key(self.keyring, version)
        except KeyConfigurationError as exc:
            raise LedgerError(
                "UNKNOWN_KEY_VERSION",
                str(exc),
                500,
                {"key_version": version},
            ) from exc

    async def seal_once(self, session: AsyncSession) -> SealResult:
        async with session.begin():
            dialect = session.bind.dialect.name if session.bind is not None else ""
            if dialect == "postgresql":
                acquired = await session.scalar(
                    text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
                    {"lock_id": SEALER_ADVISORY_LOCK_ID},
                )
                if not acquired:
                    return SealResult("busy")

            previous = await session.scalar(
                select(Checkpoint).order_by(Checkpoint.leaf_count.desc()).limit(1).with_for_update()
            )
            last_sequence = previous.last_event_sequence if previous else 0
            batch = list(
                (
                    await session.scalars(
                        select(Event)
                        .where(Event.sequence > last_sequence)
                        .order_by(Event.sequence)
                        .limit(self.batch_size)
                    )
                ).all()
            )
            if not batch:
                return SealResult("idle")

            target_sequence = batch[-1].sequence
            events = list(
                (
                    await session.scalars(
                        select(Event)
                        .where(Event.sequence <= target_sequence)
                        .order_by(Event.sequence)
                    )
                ).all()
            )
            expected_count = (previous.leaf_count if previous else 0) + len(batch)
            if len(events) != expected_count:
                raise LedgerError(
                    "EVENT_SEQUENCE_CORRUPT",
                    "event prefix does not match the expected checkpoint boundary",
                    500,
                    {"expected_count": expected_count, "actual_count": len(events)},
                )

            leaves: list[bytes] = []
            for event in events:
                calculated = leaf_hash(event_commitment_bytes(event))
                if calculated.hex() != event.leaf_hash:
                    raise LedgerError(
                        "MERKLE_NODE_CORRUPT",
                        "stored event commitment does not match immutable event fields",
                        500,
                        {"event_id": str(event.event_id), "sequence": event.sequence},
                    )
                leaves.append(calculated)

            if previous:
                previous_root = merkle_root(leaves[: previous.leaf_count]).hex()
                if previous_root != previous.root_hash:
                    raise LedgerError(
                        "CHECKPOINT_CORRUPT",
                        "last checkpoint no longer matches its immutable event prefix",
                        500,
                        {"checkpoint_id": str(previous.checkpoint_id)},
                    )
                previous_key = self._signing_key(previous.key_version)
                if not verify_checkpoint_signature(
                    checkpoint_signing_bytes(previous), previous.signature, previous_key
                ):
                    raise LedgerError(
                        "CHECKPOINT_SIGNATURE_INVALID",
                        "last checkpoint signature failed verification",
                        500,
                        {"checkpoint_id": str(previous.checkpoint_id)},
                    )

            checkpoint = Checkpoint(
                checkpoint_id=self.uuid_factory(),
                leaf_count=len(events),
                last_event_sequence=target_sequence,
                root_hash=merkle_root(leaves).hex(),
                previous_checkpoint_id=previous.checkpoint_id if previous else None,
                previous_root_hash=previous.root_hash if previous else None,
                key_version=self.current_key_version,
                created_at=self.clock(),
                signature="",
            )
            key = self._signing_key(self.current_key_version)
            checkpoint.signature = sign_checkpoint(checkpoint_signing_bytes(checkpoint), key)
            session.add(checkpoint)
            await session.flush()
            return SealResult("sealed", checkpoint)
