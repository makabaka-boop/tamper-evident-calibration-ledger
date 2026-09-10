from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, JsonValue

ShortText = Annotated[str, Field(min_length=1, max_length=128)]

# A single nighttime calibration window may fan in at most this many reports.
MAX_BATCH_REPORTS = 50

# Checkpoint increment pages default to one hundred receipts and never exceed five hundred,
# keeping each deterministic cursor page cheap to revalidate and transmit.
DEFAULT_CHECKPOINT_EVENTS_PAGE = 100
MAX_CHECKPOINT_EVENTS_PAGE = 500


class SubmitReport(BaseModel):
    business_key: ShortText
    instrument_id: ShortText
    operator_id: ShortText
    report: JsonValue


class SubmitReportBatch(BaseModel):
    reports: Annotated[
        list[SubmitReport], Field(min_length=1, max_length=MAX_BATCH_REPORTS)
    ]


class SubmitRevision(SubmitReport):
    """A report submission that explicitly succeeds an immutable event."""


class SubmitRevocation(BaseModel):
    business_key: ShortText
    operator_id: ShortText
    reason: Annotated[str, Field(min_length=1, max_length=2000)]


class VerifyRequest(BaseModel):
    receipt: dict[str, Any]


class CreateAuditPackage(BaseModel):
    instrument_id: ShortText
    idempotency_key: Annotated[str, Field(min_length=1, max_length=128)]
    checkpoint_id: UUID | None = None


class EventView(BaseModel):
    sequence: int
    event_id: UUID
    record_id: UUID
    event_type: Literal["report", "revision", "revocation"]
    business_key: str
    content_fingerprint: str
    instrument_id: str
    operator_id: str
    report_digest: str | None
    previous_event_id: UUID | None
    reason: str | None
    occurred_at: str
    leaf_hash: str


class ErrorEnvelope(BaseModel):
    error: dict[str, Any]
