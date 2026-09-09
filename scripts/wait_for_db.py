from __future__ import annotations

import asyncio
import sys

from sqlalchemy import text

from ledger.config import get_settings
from ledger.db import make_engine


async def wait() -> None:
    engine = make_engine(get_settings())
    for attempt in range(1, 31):
        try:
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            await engine.dispose()
            return
        except Exception as exc:
            if attempt == 30:
                print(f"database did not become ready: {exc}", file=sys.stderr)
                await engine.dispose()
                raise SystemExit(1) from exc
            print(f"database unavailable (attempt {attempt}/30): {exc}", file=sys.stderr)
            await asyncio.sleep(min(attempt, 5))


if __name__ == "__main__":
    asyncio.run(wait())
