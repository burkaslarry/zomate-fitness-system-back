import asyncio
from unittest.mock import MagicMock, patch

import pytest

from app.config import Settings
from app.keepalive import keepalive_loop


@pytest.mark.asyncio
async def test_keepalive_makes_multiple_attempts() -> None:
    settings = Settings(
        DATABASE_URL="postgresql+psycopg2:///x",
        PUBLIC_BASE_URL="http://example.invalid",
        KEEPALIVE_INTERVAL_SECONDS=1,
        KEEPALIVE_TIMEOUT_SECONDS=2,
        KEEPALIVE_JITTER_SECONDS=0,
    )
    stop = asyncio.Event()
    calls: list[int] = []

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url: str):
            calls.append(1)
            m = MagicMock()
            m.status_code = 200
            return m

    with patch("app.keepalive.httpx.AsyncClient", return_value=FakeClient()):
        task = asyncio.create_task(keepalive_loop(settings, stop))
        await asyncio.sleep(4.0)
        stop.set()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert len(calls) >= 2
