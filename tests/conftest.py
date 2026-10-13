"""[F007][S005] Isolated database fixtures for backend regression tests."""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app import models  # noqa: F401 — register model metadata before creating tables.


def pytest_configure(config) -> None:
    """[F007][S005] Preserve the test suite's production startup isolation."""
    import app.main as main

    main._sync_startup = lambda: None  # noqa: SLF001


@pytest.fixture
def db_session():
    """[F007][S005] Provide a fresh in-memory database; never connect to production."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as session:
            yield session
    finally:
        engine.dispose()
