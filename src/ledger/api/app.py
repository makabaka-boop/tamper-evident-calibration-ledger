from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from ledger.config import Settings, get_settings
from ledger.db import make_engine, make_session_factory, session_dependency
from ledger.domain import event_view
from ledger.errors import InvalidProofError, LedgerError
from ledger.models import Event
from ledger.proofs import build_checkpoint_view, build_receipt, verify_receipt
from ledger.schemas import SubmitReport, SubmitRevision, SubmitRevocation, VerifyRequest
from ledger.security import KeyConfigurationError
from ledger.service import EventService

logger = logging.getLogger(__name__)
Session = Annotated[AsyncSession, Depends(session_dependency)]


def error_response(request: Request, error: LedgerError) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")
    return JSONResponse(
        status_code=error.status_code,
        content={
            "error": {
                "code": error.code,
                "message": error.message,
                "details": error.details,
                "request_id": request_id,
            }
        },
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    configured = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Fail before accepting traffic when signing material is missing or malformed.
        if not configured.keyring:
            raise KeyConfigurationError("at least one HMAC key is required")
        engine = make_engine(configured)
        app.state.engine = engine
        app.state.session_factory = make_session_factory(engine)
        app.state.event_service = EventService()
        yield
        await engine.dispose()

    app = FastAPI(
        title="Tamper-evident Calibration Ledger",
        version="1.0.0",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def request_identity(request: Request, call_next):
        request.state.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(LedgerError)
    async def ledger_error_handler(request: Request, exc: LedgerError) -> JSONResponse:
        return error_response(request, exc)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        error = LedgerError(
            "INVALID_REQUEST",
            "request validation failed",
            422,
            {
                "violations": [
                    {
                        "location": [str(part) for part in item["loc"]],
                        "message": item["msg"],
                        "type": item["type"],
                    }
                    for item in exc.errors()
                ]
            },
        )
        return error_response(request, error)

    @app.exception_handler(SQLAlchemyError)
    async def database_error_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        logger.exception(
            "database operation failed", extra={"request_id": request.state.request_id}
        )
        return error_response(
            request,
            LedgerError(
                "DATABASE_UNAVAILABLE",
                "database operation failed; retry after database recovery",
                503,
                {"retryable": True},
            ),
        )

    @app.get("/health/live", tags=["health"])
    async def live() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/health/ready", tags=["health"])
    async def ready(request: Request) -> Response:
        try:
            async with request.app.state.session_factory() as session:
                await session.execute(text("SELECT 1"))
                migration = await session.scalar(text("SELECT version_num FROM alembic_version"))
            if not migration:
                raise RuntimeError("migration version is absent")
        except Exception as exc:  # readiness must convert driver and migration failures alike
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "error": {
                        "code": "DATABASE_OR_MIGRATION_UNAVAILABLE",
                        "message": str(exc),
                    },
                },
            )
        return JSONResponse({"status": "ready", "migration": str(migration)})

    @app.post("/v1/reports", tags=["events"])
    async def submit_report(
        payload: SubmitReport, response: Response, session: Session, request: Request
    ) -> dict[str, Any]:
        event, created = await request.app.state.event_service.append_report(session, payload)
        response.status_code = 201 if created else 200
        return {"created": created, "event": event_view(event), "witness_status": "pending"}

    @app.post("/v1/events/{event_id}/revisions", tags=["events"])
    async def submit_revision(
        event_id: uuid.UUID,
        payload: SubmitRevision,
        response: Response,
        session: Session,
        request: Request,
    ) -> dict[str, Any]:
        event, created = await request.app.state.event_service.append_revision(
            session, event_id, payload
        )
        response.status_code = 201 if created else 200
        return {"created": created, "event": event_view(event), "witness_status": "pending"}

    @app.post("/v1/events/{event_id}/revocations", tags=["events"])
    async def submit_revocation(
        event_id: uuid.UUID,
        payload: SubmitRevocation,
        response: Response,
        session: Session,
        request: Request,
    ) -> dict[str, Any]:
        event, created = await request.app.state.event_service.append_revocation(
            session, event_id, payload
        )
        response.status_code = 201 if created else 200
        return {"created": created, "event": event_view(event), "witness_status": "pending"}

    @app.get("/v1/events/{event_id}", tags=["proofs"])
    async def get_event(event_id: uuid.UUID, session: Session) -> dict[str, Any]:
        return await build_receipt(session, event_id, configured.keyring)

    @app.get("/v1/records/{record_id}", tags=["events"])
    async def get_record(record_id: uuid.UUID, session: Session) -> dict[str, Any]:
        events = list(
            (
                await session.scalars(
                    select(Event).where(Event.record_id == record_id).order_by(Event.sequence)
                )
            ).all()
        )
        if not events:
            raise LedgerError(
                "NOT_FOUND", "record was not found", 404, {"record_id": str(record_id)}
            )
        return {
            "record_id": str(record_id),
            "current_state": events[-1].event_type,
            "events": [event_view(item) for item in events],
        }

    @app.get("/v1/checkpoints/{checkpoint_id}", tags=["proofs"])
    async def get_checkpoint(checkpoint_id: uuid.UUID, session: Session) -> dict[str, Any]:
        return await build_checkpoint_view(session, checkpoint_id, configured.keyring)

    @app.post("/v1/verify", tags=["proofs"])
    async def verify(payload: VerifyRequest) -> dict[str, Any]:
        try:
            return verify_receipt(payload.receipt, configured.keyring)
        except KeyConfigurationError as exc:
            raise LedgerError("UNKNOWN_KEY_VERSION", str(exc), 422, {"retryable": False}) from exc
        except InvalidProofError:
            raise

    return app


app = create_app()
