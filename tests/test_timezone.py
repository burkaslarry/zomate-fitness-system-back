from datetime import datetime, timezone

from app.timezone import hk_calendar_date, now_hk


def test_hk_calendar_date_utc_naive() -> None:
    dt = datetime(2026, 5, 8, 15, 30, 0)  # naive treated as UTC
    d = hk_calendar_date(dt)
    assert d.year == 2026


def test_now_hk_tzaware() -> None:
    n = now_hk()
    assert n.tzinfo is not None
    assert "Hong_Kong" in str(n.tzinfo)


def test_hk_calendar_date_explicit_utc() -> None:
    dt = datetime(2026, 5, 8, 15, 30, tzinfo=timezone.utc)
    hk_calendar_date(dt)
