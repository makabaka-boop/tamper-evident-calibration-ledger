from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from ledger.config import get_settings
from ledger.db import make_engine, make_session_factory
from ledger.errors import LedgerError
from ledger.sealing import CheckpointSealer

logger = logging.getLogger("ledger.sealer")


async def run() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    engine = make_engine(settings)
    factory = make_session_factory(engine)
    sealer = CheckpointSealer(
        keyring=settings.keyring,
        current_key_version=settings.current_key_version,
        batch_size=settings.seal_batch_size,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(name, stop.set)
    ready_path = Path(os.environ.get("LEDGER_SEALER_READY_FILE", "/tmp/ledger-sealer-ready"))
    try:
        while not stop.is_set():
            try:
                async with factory() as session:
                    result = await sealer.seal_once(session)
                ready_path.write_text(result.status, encoding="utf-8")
                if result.status == "sealed":
                    logger.info(
                        json.dumps(
                            {
                                "event": "checkpoint_sealed",
                                "checkpoint_id": str(result.checkpoint.checkpoint_id),
                                "leaf_count": result.checkpoint.leaf_count,
                            }
                        )
                    )
            except LedgerError as exc:
                logger.error(
                    json.dumps(
                        {
                            "event": "sealing_rejected",
                            "code": exc.code,
                            "message": exc.message,
                            "details": exc.details,
                        }
                    )
                )
            except SQLAlchemyError as exc:
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
                await asyncio.wait_for(stop.wait(), timeout=settings.seal_poll_seconds)
            except TimeoutError:
                continue
    finally:
        ready_path.unlink(missing_ok=True)
        await engine.dispose()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
