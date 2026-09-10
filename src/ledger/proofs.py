from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ledger.domain import (
    checkpoint_signing_bytes,
    checkpoint_view,
    event_commitment_bytes,
    event_view,
)
from ledger.errors import InvalidProofError, LedgerError, NotFoundError
from ledger.merkle import (
    InclusionStep,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    verify_consistency,
    verify_inclusion,
)
from ledger.models import Checkpoint, Event
from ledger.security import KeyConfigurationError, require_key, verify_checkpoint_signature


def _decode_hash(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise InvalidProofError(f"{field} must be a hexadecimal string", {"field": field})
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise InvalidProofError(f"{field} is not valid hexadecimal", {"field": field}) from exc
    if len(decoded) != 32:
        raise InvalidProofError(f"{field} must encode 32 bytes", {"field": field})
    return decoded


def _verify_signed_checkpoint(data: dict[str, Any], keyring: Mapping[str, bytes]) -> None:
    try:
        version = str(data["key_version"])
        signature = str(data["signature"])
        key = require_key(keyring, version)
        payload = checkpoint_signing_bytes(data)
    except KeyConfigurationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidProofError("checkpoint fields are malformed") from exc
    if not verify_checkpoint_signature(payload, signature, key):
        raise InvalidProofError(
            "checkpoint HMAC signature does not match",
            {"checkpoint_id": str(data.get("checkpoint_id", "unknown"))},
        )


def verify_receipt(receipt: dict[str, Any], keyring: Mapping[str, bytes]) -> dict[str, Any]:
    """Verify a receipt using only supplied data and a versioned HMAC keyring."""

    try:
        event = receipt["event"]
        status = receipt["witness_status"]
        claimed_leaf = _decode_hash(event["leaf_hash"], "event.leaf_hash")
        calculated_leaf = leaf_hash(event_commitment_bytes(event))
    except (InvalidProofError, KeyConfigurationError):
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidProofError("event commitment fields are malformed") from exc
    if claimed_leaf != calculated_leaf:
        raise InvalidProofError("event commitment hash does not match its public fields")
    if status == "pending":
        if receipt.get("checkpoint") is not None or receipt.get("inclusion_proof") is not None:
            raise InvalidProofError("a pending receipt cannot contain a checkpoint proof")
        return {"valid": True, "witnessed": False}
    if status != "sealed":
        raise InvalidProofError("unknown witness status", {"witness_status": status})

    try:
        checkpoint = receipt["checkpoint"]
        proof = receipt["inclusion_proof"]
        _verify_signed_checkpoint(checkpoint, keyring)
        expected_root = _decode_hash(checkpoint["root_hash"], "checkpoint.root_hash")
        steps = [
            InclusionStep(
                item["side"],
                _decode_hash(item["hash"], f"inclusion_proof.path[{index}].hash"),
            )
            for index, item in enumerate(proof["path"])
        ]
        if any(step.side not in {"left", "right"} for step in steps):
            raise InvalidProofError("inclusion proof contains an invalid side")
        if int(proof["tree_size"]) != int(checkpoint["leaf_count"]):
            raise InvalidProofError("inclusion proof tree size does not match checkpoint")
        included = verify_inclusion(
            calculated_leaf,
            int(proof["leaf_index"]),
            int(proof["tree_size"]),
            steps,
            expected_root,
        )
    except (InvalidProofError, KeyConfigurationError):
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidProofError("inclusion proof fields are malformed") from exc
    if not included:
        raise InvalidProofError("event is not included in the checkpoint root")

    previous_id = checkpoint.get("previous_checkpoint_id")
    consistency = receipt.get("consistency_proof")
    if previous_id is None:
        if checkpoint.get("previous_root_hash") is not None:
            raise InvalidProofError("first checkpoint cannot contain a predecessor root")
        if consistency is not None:
            raise InvalidProofError("first checkpoint cannot have a consistency predecessor")
    else:
        if not isinstance(consistency, dict):
            raise InvalidProofError("adjacent checkpoint consistency proof is missing")
        try:
            old_checkpoint = consistency["old_checkpoint"]
            _verify_signed_checkpoint(old_checkpoint, keyring)
            if str(old_checkpoint["checkpoint_id"]) != str(previous_id):
                raise InvalidProofError("consistency proof is not for the adjacent checkpoint")
            if checkpoint.get("previous_root_hash") != old_checkpoint.get("root_hash"):
                raise InvalidProofError("checkpoint predecessor root linkage is broken")
            if str(consistency["new_checkpoint_id"]) != str(checkpoint["checkpoint_id"]):
                raise InvalidProofError("consistency proof target checkpoint does not match")
            hashes = [
                _decode_hash(item, f"consistency_proof.hashes[{index}]")
                for index, item in enumerate(consistency["hashes"])
            ]
            old_size = int(consistency["old_size"])
            new_size = int(consistency["new_size"])
            if old_size != int(old_checkpoint["leaf_count"]):
                raise InvalidProofError("old consistency size does not match predecessor")
            if new_size != int(checkpoint["leaf_count"]):
                raise InvalidProofError("new consistency size does not match checkpoint")
            consistent = verify_consistency(
                old_size,
                new_size,
                _decode_hash(old_checkpoint["root_hash"], "old_checkpoint.root_hash"),
                expected_root,
                hashes,
            )
        except (InvalidProofError, KeyConfigurationError):
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidProofError("consistency proof fields are malformed") from exc
        if not consistent:
            raise InvalidProofError("checkpoint roots are not append-only consistent")

    return {
        "valid": True,
        "witnessed": True,
        "checkpoint_id": str(checkpoint["checkpoint_id"]),
    }


async def _validated_prefix(
    session: AsyncSession, checkpoint: Checkpoint, keyring: Mapping[str, bytes]
) -> tuple[list[Event], list[bytes]]:
    events = list(
        (
            await session.scalars(
                select(Event)
                .where(Event.sequence <= checkpoint.last_event_sequence)
                .order_by(Event.sequence)
            )
        ).all()
    )
    if len(events) != checkpoint.leaf_count or not events:
        raise LedgerError(
            "CHECKPOINT_CORRUPT",
            "checkpoint boundary does not match the event prefix",
            500,
            {"checkpoint_id": str(checkpoint.checkpoint_id)},
        )
    leaves: list[bytes] = []
    for item in events:
        calculated = leaf_hash(event_commitment_bytes(item))
        if calculated.hex() != item.leaf_hash:
            raise LedgerError(
                "MERKLE_NODE_CORRUPT",
                "stored event commitment does not match immutable event fields",
                500,
                {"event_id": str(item.event_id), "sequence": item.sequence},
            )
        leaves.append(calculated)
    if merkle_root(leaves).hex() != checkpoint.root_hash:
        raise LedgerError(
            "CHECKPOINT_CORRUPT",
            "recomputed Merkle root does not match checkpoint",
            500,
            {"checkpoint_id": str(checkpoint.checkpoint_id)},
        )
    try:
        key = require_key(keyring, checkpoint.key_version)
    except KeyConfigurationError as exc:
        raise LedgerError(
            "UNKNOWN_KEY_VERSION",
            str(exc),
            500,
            {"key_version": checkpoint.key_version},
        ) from exc
    if not verify_checkpoint_signature(
        checkpoint_signing_bytes(checkpoint), checkpoint.signature, key
    ):
        raise LedgerError(
            "CHECKPOINT_SIGNATURE_INVALID",
            "stored checkpoint signature failed verification",
            500,
            {"checkpoint_id": str(checkpoint.checkpoint_id)},
        )
    return events, leaves


async def build_receipt(
    session: AsyncSession, event_id: UUID, keyring: Mapping[str, bytes]
) -> dict[str, Any]:
    event = await session.scalar(select(Event).where(Event.event_id == event_id))
    if not event:
        raise NotFoundError("event", str(event_id))
    if leaf_hash(event_commitment_bytes(event)).hex() != event.leaf_hash:
        raise LedgerError(
            "MERKLE_NODE_CORRUPT",
            "stored event commitment does not match immutable event fields",
            500,
            {"event_id": str(event.event_id), "sequence": event.sequence},
        )
    checkpoint = await session.scalar(
        select(Checkpoint)
        .where(Checkpoint.last_event_sequence >= event.sequence)
        .order_by(Checkpoint.leaf_count.desc())
        .limit(1)
    )
    if not checkpoint:
        return {
            "event": event_view(event),
            "witness_status": "pending",
            "checkpoint": None,
            "inclusion_proof": None,
            "consistency_proof": None,
        }
    return await build_receipt_at_checkpoint(session, event, checkpoint, keyring)


def _sealed_receipt(
    event: Event,
    index: int,
    checkpoint: Checkpoint,
    leaves: Sequence[bytes],
    consistency_bundle: dict[str, Any] | None,
) -> dict[str, Any]:
    """Render the canonical sealed receipt for an event inside a validated prefix."""

    path = inclusion_proof(leaves, index)
    return {
        "event": event_view(event),
        "witness_status": "sealed",
        "checkpoint": checkpoint_view(checkpoint),
        "inclusion_proof": {
            "leaf_index": index,
            "tree_size": checkpoint.leaf_count,
            "path": [{"side": item.side, "hash": item.hash.hex()} for item in path],
        },
        "consistency_proof": consistency_bundle,
    }


async def build_receipt_at_checkpoint(
    session: AsyncSession,
    event: Event,
    checkpoint: Checkpoint,
    keyring: Mapping[str, bytes],
) -> dict[str, Any]:
    """Build a sealed receipt pinned to an already chosen checkpoint boundary."""

    events, leaves = await _validated_prefix(session, checkpoint, keyring)
    try:
        index = next(i for i, item in enumerate(events) if item.event_id == event.event_id)
    except StopIteration as exc:
        raise LedgerError(
            "CHECKPOINT_CORRUPT",
            "checkpoint boundary does not contain the event",
            500,
            {"checkpoint_id": str(checkpoint.checkpoint_id), "event_id": str(event.event_id)},
        ) from exc
    consistency_bundle = await build_consistency_bundle(session, checkpoint, leaves, keyring)
    return _sealed_receipt(event, index, checkpoint, leaves, consistency_bundle)


async def build_consistency_bundle(
    session: AsyncSession,
    checkpoint: Checkpoint,
    leaves: Sequence[bytes],
    keyring: Mapping[str, bytes],
) -> dict[str, Any] | None:
    if not checkpoint.previous_checkpoint_id:
        return None
    previous = await session.get(Checkpoint, checkpoint.previous_checkpoint_id)
    if not previous:
        raise LedgerError(
            "CHECKPOINT_CHAIN_BROKEN",
            "adjacent checkpoint record is missing",
            500,
            {"checkpoint_id": str(checkpoint.checkpoint_id)},
        )
    await _validated_prefix(session, previous, keyring)
    if previous.root_hash != checkpoint.previous_root_hash:
        raise LedgerError(
            "CHECKPOINT_CHAIN_BROKEN",
            "adjacent checkpoint root linkage is inconsistent",
            500,
            {"checkpoint_id": str(checkpoint.checkpoint_id)},
        )
    return {
        "old_checkpoint": checkpoint_view(previous),
        "new_checkpoint_id": str(checkpoint.checkpoint_id),
        "old_size": previous.leaf_count,
        "new_size": checkpoint.leaf_count,
        "hashes": [item.hex() for item in consistency_proof(leaves, previous.leaf_count)],
    }


async def build_checkpoint_view(
    session: AsyncSession, checkpoint_id: UUID, keyring: Mapping[str, bytes]
) -> dict[str, Any]:
    checkpoint = await session.get(Checkpoint, checkpoint_id)
    if not checkpoint:
        raise NotFoundError("checkpoint", str(checkpoint_id))
    _events, leaves = await _validated_prefix(session, checkpoint, keyring)
    consistency_bundle = await build_consistency_bundle(session, checkpoint, leaves, keyring)
    return {"checkpoint": checkpoint_view(checkpoint), "consistency_proof": consistency_bundle}


async def build_checkpoint_event_page(
    session: AsyncSession,
    checkpoint_id: UUID,
    after_sequence: int | None,
    limit: int,
    keyring: Mapping[str, bytes],
) -> dict[str, Any]:
    """Build one deterministic page of the increment a checkpoint newly covers.

    The increment is the sequence range after the predecessor checkpoint's boundary up to and
    including this checkpoint's ``last_event_sequence`` (the full prefix for the first
    checkpoint). Both boundaries come from immutable checkpoint rows and the page is sliced
    from the Merkle-validated prefix, so events or checkpoints committed later can never
    change the result of repeating the same page request.
    """

    checkpoint = await session.get(Checkpoint, checkpoint_id)
    if not checkpoint:
        raise NotFoundError("checkpoint", str(checkpoint_id))
    if checkpoint.previous_checkpoint_id is not None:
        previous = await session.get(Checkpoint, checkpoint.previous_checkpoint_id)
        if previous is None:
            raise LedgerError(
                "CHECKPOINT_CHAIN_BROKEN",
                "adjacent checkpoint record is missing",
                500,
                {"checkpoint_id": str(checkpoint.checkpoint_id)},
            )
        increment_start = previous.last_event_sequence
    else:
        increment_start = 0
    upper_bound = checkpoint.last_event_sequence
    cursor = increment_start if after_sequence is None else after_sequence
    if cursor < increment_start:
        raise LedgerError(
            "INVALID_CURSOR",
            "after_sequence is before the checkpoint's increment start",
            422,
            {
                "checkpoint_id": str(checkpoint.checkpoint_id),
                "after_sequence": cursor,
                "increment_start": increment_start,
                "upper_bound": upper_bound,
            },
        )
    if cursor > upper_bound:
        raise LedgerError(
            "INVALID_CURSOR",
            "after_sequence is beyond the checkpoint's fixed upper bound",
            422,
            {
                "checkpoint_id": str(checkpoint.checkpoint_id),
                "after_sequence": cursor,
                "increment_start": increment_start,
                "upper_bound": upper_bound,
            },
        )

    events, leaves = await _validated_prefix(session, checkpoint, keyring)
    consistency_bundle = await build_consistency_bundle(session, checkpoint, leaves, keyring)
    candidates = [
        (index, item) for index, item in enumerate(events) if item.sequence > cursor
    ]
    has_more = len(candidates) > limit
    page = candidates[:limit]
    return {
        "checkpoint_id": str(checkpoint.checkpoint_id),
        "items": [
            _sealed_receipt(item, index, checkpoint, leaves, consistency_bundle)
            for index, item in page
        ],
        # A finished page (including an empty increment) reports no cursor rather than
        # inventing one the client could mistake for a readable position.
        "next_after_sequence": page[-1][1].sequence if has_more else None,
        "has_more": has_more,
    }
