"""[F003][S002] Coach first-booking uses coach-picked day, not legacy weekday."""

from datetime import date

from app.enrollment_schedule import enumerate_lesson_dates


def test_first_booking_weekday_aligns_to_picked_day() -> None:
    """Picking Monday 2026-07-21 must not snap to Thursday from old lesson_weekdays."""
    picked = date(2026, 7, 21)  # Tuesday (weekday=1)
    assert picked.weekday() == 1
    ws = [picked.weekday()]
    dates = enumerate_lesson_dates(picked, ws, 10)
    assert dates[0] == picked
    assert all(d.weekday() == 1 for d in dates)
