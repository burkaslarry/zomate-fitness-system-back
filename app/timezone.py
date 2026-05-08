"""Hong Kong wall-clock helpers for attendance and scheduling."""

from __future__ import annotations

from datetime import date, datetime, timezone as dt_timezone
from zoneinfo import ZoneInfo

HK = ZoneInfo("Asia/Hong_Kong")


def now_hk() -> datetime:
    """Current instant as timezone-aware Asia/Hong_Kong."""
    return datetime.now(HK)


def hk_calendar_date(dt: datetime | None = None) -> date:
    """Calendar date in Hong Kong for *dt* (default: now).

    Naive datetimes are interpreted as **UTC** (matches ``datetime.utcnow()``).
    """
    if dt is None:
        return now_hk().date()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=dt_timezone.utc).astimezone(HK).date()
    return dt.astimezone(HK).date()


def utc_to_hk(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=dt_timezone.utc).astimezone(HK)
    return dt.astimezone(HK)
