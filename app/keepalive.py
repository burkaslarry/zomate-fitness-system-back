"""Background self-ping to PUBLIC_BASE_URL/api/health for Render wake-ups."""

from __future__ import annotations

import asyncio
import random

import httpx

from .config import Settings
from .logutil import log_event


async def keepalive_loop(settings: Settings, stop: asyncio.Event) -> None:
    base = (settings.public_base_url or "").rstrip("/")
    if not base:
        log_event("keepalive_disabled", reason="PUBLIC_BASE_URL unset")
        return

    interval = max(1, int(settings.keepalive_interval_seconds))
    timeout = max(0.5, float(settings.keepalive_timeout_seconds))
    jitter = max(0.0, float(settings.keepalive_jitter_seconds))

    url = f"{base}/api/health"
    log_event("keepalive_started", url=url, interval_seconds=interval)

    loop = asyncio.get_event_loop()

    while not stop.is_set():
        started = loop.time()
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.get(url)
            elapsed_ms = round((loop.time() - started) * 1000, 2)
            log_event(
                "keepalive_ping_ok",
                status_code=r.status_code,
                latency_ms=elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = round((loop.time() - started) * 1000, 2)
            log_event("keepalive_ping_fail", error=str(exc), latency_ms=elapsed_ms)

        jitter_s = random.uniform(-jitter, jitter) if jitter else 0.0
        # Minimum 1s between iterations so VERIFY scripts can use KEEPALIVE_INTERVAL_SECONDS=2.
        sleep_for = max(1.0, interval + jitter_s)
        try:
            await asyncio.wait_for(stop.wait(), timeout=sleep_for)
            return
        except asyncio.TimeoutError:
            continue
