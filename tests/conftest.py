"""Disable heavy DB bootstrap during pytest unless integration tests opt in."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def pytest_configure(config) -> None:
    import app.main as main

    main._sync_startup = lambda: None  # noqa: SLF001
