"""[F007][S002]
Feature: Lesson ledger (fractional credits)
Step: 0.5-lesson quantize, session duration → credit, booking availability
Logic: 1 hour of class = 1 lesson credit; ledger may show 9.5 堂.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy.orm import Session

from .models import Attendance, CourseEnrollment
from .timezone import now_hk

COACH_LESSON_DURATIONS: tuple[float, ...] = (0.5, 1.0, 1.5, 2.0)
_DURATION_MATCH_EPS = 0.06


def quantize_lesson_credits(value: float) -> float:
    """Round to nearest 0.5 lesson."""
    return round(float(value) * 2.0) / 2.0


def format_lesson_credits(value: float) -> str:
    """Human-readable 堂數 (e.g. 9.5, 10)."""
    q = quantize_lesson_credits(value)
    if abs(q - round(q)) < 1e-9:
        return str(int(round(q)))
    return f"{q:.1f}".rstrip("0").rstrip(".")


def interval_credit_hours(start: datetime, end: datetime) -> float:
    """[F003][S003] Map scheduled interval to redeemable lesson credits."""
    raw = max(0.25, (end - start).total_seconds() / 3600.0)
    for allowed in COACH_LESSON_DURATIONS:
        if abs(raw - allowed) < _DURATION_MATCH_EPS:
            return allowed
    return quantize_lesson_credits(raw)


def allowed_duration_hours(available_credits: float) -> list[float]:
    """[F003][S003] Durations coach may pick given remaining + unbooked credits."""
    cap = quantize_lesson_credits(max(0.0, available_credits))
    return [d for d in COACH_LESSON_DURATIONS if d <= cap + 1e-9]


def _attended_dates_for_course(db: Session, course_id: int) -> set[date]:
  rows = (
      db.query(Attendance.session_calendar_date)
      .filter(Attendance.course_id == course_id)
      .all()
  )
  return {r[0] for r in rows if r[0] is not None}


def student_scheduled_unredeemed_credits(
    db: Session,
    student_id: int,
    *,
    exclude_enrollment_id: int | None = None,
    exclude_original_date: date | None = None,
) -> float:
    """[F003][S009] Sum future slot durations not yet checked in (soft reservation)."""
    from .enrollment_schedule import confirmed_lesson_slots

    today = now_hk().date()
    enrollments = (
        db.query(CourseEnrollment)
        .filter(
            CourseEnrollment.student_id == student_id,
            CourseEnrollment.coach_time_confirmed.is_(True),
        )
        .all()
    )
    total = 0.0
    for enr in enrollments:
        attended = _attended_dates_for_course(db, enr.id)
        for start, end, original in confirmed_lesson_slots(db, enr):
            slot_day = start.date()
            if slot_day < today:
                continue
            if original in attended or slot_day in attended:
                continue
            if exclude_enrollment_id is not None and enr.id == exclude_enrollment_id:
                if exclude_original_date is None or original == exclude_original_date:
                    continue
            total += interval_credit_hours(start, end)
    return quantize_lesson_credits(total)


def lesson_credits_available(db: Session, student_id: int, balance: float) -> float:
    """Ledger balance minus credits already committed to future sessions."""
    held = student_scheduled_unredeemed_credits(db, student_id)
    return quantize_lesson_credits(max(0.0, balance - held))


def course_redeemed_credits(db: Session, enrollment: CourseEnrollment) -> float:
    """[F003][S003] Checked-in credits for one course package (duration-aware)."""
    from .enrollment_schedule import confirmed_lesson_slots

    credit_by_day: dict[date, float] = {}
    for start, end, original in confirmed_lesson_slots(db, enrollment):
        credit = interval_credit_hours(start, end)
        credit_by_day[original] = credit
        credit_by_day[start.date()] = credit
    rows = (
        db.query(Attendance.session_calendar_date)
        .filter(Attendance.course_id == enrollment.id)
        .all()
    )
    total = 0.0
    for (slot_day,) in rows:
        if slot_day is None:
            continue
        total += credit_by_day.get(slot_day, 1.0)
    return quantize_lesson_credits(total)