from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from ledger.audit.service import AuditPackageService
from ledger.config import get_settings
from ledger.db import make_engine, make_session_factory
from ledger.security import KeyConfigurationError

logger = logging.getLogger("ledger.exporter")


async def run() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Fail before claiming tasks when receipt-signing material is missing or malformed.
    if not settings.keyring:
        raise KeyConfigurationError("at least one HMAC key is required")
    engine = make_engine(settings)
    factory = make_session_factory(engine)
    service = AuditPackageService()
    lease = timedelta(seconds=settings.export_lease_seconds)
    worker_id = os.environ.get("LEDGER_EXPORTER_ID") or f"exporter-{uuid.uuid4().hex[:12]}"
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(name, stop.set)
    ready_path = Path(os.environ.get("LEDGER_EXPORTER_READY_FILE", "/tmp/ledger-exporter-ready"))
    try:
        while not stop.is_set():
            try:
                # Converge cancelling tasks whose owning worker died (including tasks that
                # were already cancelling when this process started) before claiming work.
                async with factory() as session:
                    settled = await service.settle_stale_cancelling(session)
                for package in settled:
                    logger.info(
                        json.dumps(
                            {
                                "event": "audit_package_cancel_confirmed",
                                "package_id": str(package.package_id),
                                "reason": "lease_expired",
                                "attempt_count": package.attempt_count,
                            }
                        )
                    )
                async with factory() as session:
                    claimed = await service.claim_package(
                        session, worker_id=worker_id, lease_duration=lease
                    )
                if claimed is not None:
                    status = await service.build_once(
                        factory, claimed, settings.keyring
                    )
                    if status == "ready":
                        logger.info(
                            json.dumps(
                                {
                                    "event": "audit_package_ready",
                                    "package_id": str(claimed.package_id),
                                    "attempt_count": claimed.attempt_count,
                                }
                            )
                        )
                    elif status == "cancelled":
                        logger.info(
                            json.dumps(
                                {
                                    "event": "audit_package_cancel_confirmed",
                                    "package_id": str(claimed.package_id),
                                    "reason": "requested",
                                    "attempt_count": claimed.attempt_count,
                                }
                            )
                        )
                    elif status == "superseded":
                        # The lease was lost and another path already settled the task;
                        # it owns the single confirmation/failure log.
                        logger.info(
                            json.dumps(
                                {
                                    "event": "audit_package_claim_superseded",
                                    "package_id": str(claimed.package_id),
                                }
                            )
                        )
                    else:
                        logger.error(
                            json.dumps(
                                {
                                    "event": "audit_package_failed",
                                    "package_id": str(claimed.package_id),
                                }
                            )
                        )
                await asyncio.to_thread(ready_path.write_text, "ok", encoding="utf-8")
            except SQLAlchemyError as exc:
                # Do not mark the task failed: the lease expires and any worker reclaims it.
                logger.error(
                    json.dumps(
                        {
                            "event": "database_unavailable",
                            "message": str(exc),
                            "retryable": True,
                        }
                    )
                )
            try:
                await asyncio.wait_for(stop.wait(), timeout=settings.export_poll_seconds)
            except TimeoutError:
                continue
    finally:
        await asyncio.to_thread(ready_path.unlink, missing_ok=True)
        await engine.dispose()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
