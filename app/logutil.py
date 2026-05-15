"""[F007][S004]
Feature: Backend platform (FastAPI & PostgreSQL)
Step: (see Logic)
Logic: Structured logging, instance id, log_event helper.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
from typing import Any

_logger = logging.getLogger("zomate")


def configure_logging(level: str | None = None) -> None:
    lvl = getattr(logging, (level or "INFO").upper(), logging.INFO)
    root = logging.getLogger()
    if root.handlers:
        root.setLevel(lvl)
        return
    logging.basicConfig(
        level=lvl,
        format="%(message)s",
        stream=sys.stdout,
    )
    root.setLevel(lvl)


def instance_id() -> str:
    return os.environ.get("INSTANCE_ID") or socket.gethostname()


def log_event(event: str, **fields: Any) -> None:
    payload = {"event": event, "instance_id": instance_id(), **fields}
    _logger.info(json.dumps(payload, ensure_ascii=False, default=str))
