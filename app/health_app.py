"""Liveness payload for /health and /api/health (no database)."""

from __future__ import annotations

import time

_monotonic_start = time.monotonic()
_wall_start = time.time()


def uptime_seconds() -> float:
    return time.monotonic() - _monotonic_start


def liveness_payload(instance_id: str) -> dict:
    return {
        "status": "ok",
        "ts": int(time.time()),
        "uptime_seconds": round(uptime_seconds(), 3),
        "instance_id": instance_id,
    }
