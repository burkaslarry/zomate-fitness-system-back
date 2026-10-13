"""[F009][S006]
Feature: Scheduled course & enrollment PINs
Step: Regression — long series lesson dates for check-in / today-lesson picker
Logic: ``get_lesson_dates_for_enrollment`` must return ``total_lessons`` dates up to scheduled-package cap 30.
"""

from datetime import date, datetime, time
from types import SimpleNamespace

from app.enrollment_schedule import enumerate_lesson_dates, get_lesson_dates_for_enrollment


def test_enumerate_lesson_dates_30_mondays() -> None:
    """[F009][S006] Preserve the thirty-lesson weekday regression."""
    start = date(2026, 5, 18)  # Monday
    dates = enumerate_lesson_dates(start, [0], 30)
    assert len(dates) == 30
    assert dates[0] == start
    assert all(d.weekday() == 0 for d in dates)


def test_get_lesson_dates_matches_total_lessons_30() -> None:
    """[F009][S006] Verify the current enrollment helper after the course model merge."""
    start = date(2026, 5, 18)
    course = SimpleNamespace(
        lesson_weekdays="0",
        series_start_date=start,
        scheduled_start=datetime.combine(start, time(10, 0)),
        total_lessons=30,
    )
    ld = get_lesson_dates_for_enrollment(course)
    assert len(ld) == 30
    assert ld[-1] == date(2026, 12, 7)


def test_get_lesson_dates_schema_cap_30() -> None:
    """[F009][S006] Preserve the enrollment schema's thirty-lesson cap."""
    start = date(2026, 1, 5)
    course = SimpleNamespace(
        lesson_weekdays="0",
        series_start_date=start,
        scheduled_start=datetime.combine(start, time(9, 0)),
        total_lessons=120,
    )
    ld = get_lesson_dates_for_enrollment(course)
    assert len(ld) == 30
