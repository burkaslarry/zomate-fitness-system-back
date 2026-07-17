"""[F003][S002] Coach booking day + quarter-hour start validation."""

from datetime import date

import pytest
from pydantic import ValidationError

from app.enrollment_schedule import enumerate_lesson_dates
from app.schemas import CoachBookSession


def test_first_booking_weekday_aligns_to_picked_day() -> None:
    picked = date(2026, 7, 21)
    ws = [picked.weekday()]
    dates = enumerate_lesson_dates(picked, ws, 10)
    assert dates[0] == picked


def test_coach_book_session_accepts_quarter_hour_start() -> None:
    payload = CoachBookSession(
        enrollment_id=1,
        day=date(2026, 7, 22),
        start_hour=12,
        start_minute=15,
        duration_hours=1.0,
    )
    assert payload.start_minute == 15


def test_coach_book_session_rejects_invalid_minute() -> None:
    with pytest.raises(ValidationError):
        CoachBookSession(
            enrollment_id=1,
            day=date(2026, 7, 22),
            start_hour=12,
            start_minute=10,
            duration_hours=1.0,
        )
