"""[F009][S002]
Feature: Scheduled course & enrollment PINs
Step: Lesson calendar helpers for merged CourseEnrollment rows
Logic: Expand weekdays, active-window checks, and CourseOut projection.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta

from .models import CourseEnrollment
from .schemas import CourseEnrollmentOut, CourseOut, InstallmentSegmentPinOut
from .timezone import HK


def parse_lesson_weekdays_str(raw: str | None) -> list[int]:
    if not raw or not str(raw).strip():
        return [0]
    out: list[int] = []
    for part in str(raw).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            v = int(part)
        except ValueError:
            continue
        if 0 <= v <= 6:
            out.append(v)
    return sorted(set(out)) if out else [0]


def enumerate_lesson_dates(start: date, weekdays: list[int], count: int) -> list[date]:
    """[F009][S001] Expand ``count`` lesson calendar dates from ``start`` honoring weekday set."""
    if count < 1:
        return []
    wd_set = set(w for w in weekdays if 0 <= w <= 6)
    if not wd_set:
        wd_set = {start.weekday()}
    dates: list[date] = []
    d = start
    max_days = max(800, count * 14 + 60)
    guard = 0
    while len(dates) < count and guard < max_days:
        if d.weekday() in wd_set:
            dates.append(d)
            if len(dates) >= count:
                break
        d += timedelta(days=1)
        guard += 1
    return dates


def get_lesson_dates_for_enrollment(enr: CourseEnrollment) -> list[date]:
    """[F009][S002] Expand series dates for check-in and today-lesson picker."""
    ws = parse_lesson_weekdays_str(enr.lesson_weekdays)
    start = enr.series_start_date or enr.scheduled_start.date()
    try:
        n = int(enr.total_lessons)
    except (TypeError, ValueError):
        n = 1
    n = max(1, min(30, n))
    if n <= 1 and (not enr.lesson_weekdays or enr.lesson_weekdays == "0"):
        return [enr.scheduled_start.date()]
    return enumerate_lesson_dates(start, ws, n)


def enrollment_active_at_now(enr: CourseEnrollment, now: datetime) -> bool:
    if now.tzinfo is None:
        now_local = now.replace(tzinfo=HK)
    else:
        now_local = now.astimezone(HK)
    d = now_local.date()
    if d not in get_lesson_dates_for_enrollment(enr):
        return False
    t_start = enr.scheduled_start.time()
    t_end = enr.scheduled_end.time()
    t = now_local.time()
    if t_start <= t_end:
        return t_start <= t <= t_end
    return t >= t_start or t <= t_end


def parse_segment_pins_json(raw: str | None) -> list[InstallmentSegmentPinOut]:
    """[F002][S001] Deserialize ``CourseEnrollment.segment_pins_json`` for API responses."""
    if not raw:
        return []
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(rows, list):
        return []
    out: list[InstallmentSegmentPinOut] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            ino = int(row["installment_no"])
            lesson_from = int(row["lesson_from"])
            lesson_to = int(row["lesson_to"])
            pr = row.get("paid")
            if pr is None:
                paid_bool = ino <= 1
            else:
                paid_bool = bool(pr)
            reminder_raw = row.get("reminder_lesson")
            reminder_lesson = int(reminder_raw) if reminder_raw is not None else max(lesson_from, lesson_to - 1)
            out.append(
                InstallmentSegmentPinOut(
                    installment_no=ino,
                    lesson_from=lesson_from,
                    lesson_to=lesson_to,
                    pin=str(row["pin"]).strip(),
                    paid=paid_bool,
                    reminder_lesson=reminder_lesson,
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out


def enrollment_to_out(enr: CourseEnrollment) -> CourseOut:
    """[F009][S003] Project one enrollment as CourseOut (id = enrollment.id, single student)."""
    branch = enr.branch
    coach = enr.coach
    st = enr.student
    segs = parse_segment_pins_json(getattr(enr, "segment_pins_json", None))
    enrollments = [
        CourseEnrollmentOut(
            student_id=st.id,
            student_name=st.full_name,
            student_phone=st.phone,
            checkin_pin=enr.checkin_pin,
            installment_segments=segs,
        )
    ]
    ws = parse_lesson_weekdays_str(getattr(enr, "lesson_weekdays", None))
    total = getattr(enr, "total_lessons", None) or 1
    return CourseOut(
        id=enr.id,
        title=enr.title,
        branch_id=enr.branch_id,
        branch_name=branch.name,
        branch_address=branch.address,
        coach_id=enr.coach_id,
        coach_name=coach.full_name,
        scheduled_start=enr.scheduled_start,
        scheduled_end=enr.scheduled_end,
        created_at=enr.created_at,
        total_lessons=int(total),
        lesson_weekdays=ws,
        series_start_date=enr.series_start_date,
        series_end_date=enr.series_end_date,
        enrollments=enrollments,
    )
