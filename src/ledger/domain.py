from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ledger.canonical import canonical_json
from ledger.models import Checkpoint, Event


def utc_now() -> datetime:
    return datetime.now(UTC)


def isoformat_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def event_commitment(event: Event | dict[str, Any]) -> dict[str, Any]:
    get = event.get if isinstance(event, dict) else lambda key: getattr(event, key)
    occurred = get("occurred_at")
    if isinstance(occurred, str):
        occurred_text = isoformat_utc(datetime.fromisoformat(occurred.replace("Z", "+00:00")))
    else:
        occurred_text = isoformat_utc(occurred)
    return {
        "schema_version": 1,
        "event_id": str(get("event_id")),
        "record_id": str(get("record_id")),
        "event_type": get("event_type"),
        "business_key": get("business_key"),
        "content_fingerprint": get("content_fingerprint"),
        "instrument_id": get("instrument_id"),
        "operator_id": get("operator_id"),
        "report_digest": get("report_digest"),
        "previous_event_id": (
            str(get("previous_event_id")) if get("previous_event_id") is not None else None
        ),
        "reason": get("reason"),
        "occurred_at": occurred_text,
    }


def event_commitment_bytes(event: Event | dict[str, Any]) -> bytes:
    return canonical_json(event_commitment(event))


def event_view(event: Event) -> dict[str, Any]:
    result = event_commitment(event)
    result.pop("schema_version")
    return {
        "sequence": event.sequence,
        **result,
        "leaf_hash": event.leaf_hash,
    }


def checkpoint_payload(checkpoint: Checkpoint | dict[str, Any]) -> dict[str, Any]:
    get = checkpoint.get if isinstance(checkpoint, dict) else lambda key: getattr(checkpoint, key)
    created = get("created_at")
    if isinstance(created, str):
        created_text = isoformat_utc(datetime.fromisoformat(created.replace("Z", "+00:00")))
    else:
        created_text = isoformat_utc(created)
    return {
        "schema_version": 1,
        "checkpoint_id": str(get("checkpoint_id")),
        "leaf_count": get("leaf_count"),
        "last_event_sequence": get("last_event_sequence"),
        "root_hash": get("root_hash"),
        "previous_checkpoint_id": (
            str(get("previous_checkpoint_id"))
            if get("previous_checkpoint_id") is not None
            else None
        ),
        "previous_root_hash": get("previous_root_hash"),
        "key_version": get("key_version"),
        "created_at": created_text,
    }


def checkpoint_signing_bytes(checkpoint: Checkpoint | dict[str, Any]) -> bytes:
    return canonical_json(checkpoint_payload(checkpoint))


def checkpoint_view(checkpoint: Checkpoint) -> dict[str, Any]:
    return {**checkpoint_payload(checkpoint), "signature": checkpoint.signature}
