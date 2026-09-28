"""[F003][S009] One-lesson cancellation and reschedule keep the enrollment series intact."""

from datetime import date, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.coach_sessions import build_coach_session_rows
from app.database import Base
from app.models import Branch, Coach, CourseCategory, CourseEnrollment, CourseSessionOverride, Student


def _series_fixture() -> tuple[Session, Coach, CourseEnrollment]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    branch = Branch(name="TST", code="OVERRIDE", address="a", active=True)
    coach = Coach(full_name="Coach", phone="98880001", branch=branch, active=True)
    category = CourseCategory(name="Pilates", is_active=True, is_deleted=False, created_by_role="test")
    student = Student(full_name="Steven", phone="98880002")
    db.add_all([branch, coach, category, student])
    db.flush()
    enrollment = CourseEnrollment(
        title="Pilates · Steven",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=student.id,
        scheduled_start=datetime(2026, 10, 5, 10, 0),
        scheduled_end=datetime(2026, 10, 5, 11, 0),
        total_lessons=3,
        lesson_weekdays="0",
        series_start_date=date(2026, 10, 5),
        series_end_date=date(2026, 10, 19),
        checkin_pin="10192",
        coach_time_confirmed=True,
    )
    db.add(enrollment)
    db.commit()
    return db, coach, enrollment


def test_cancel_one_lesson_keeps_other_series_dates() -> None:
    db, coach, enrollment = _series_fixture()
    db.add(
        CourseSessionOverride(
            enrollment_id=enrollment.id,
            original_date=date(2026, 10, 12),
            action="cancelled",
        )
    )
    db.commit()

    rows = build_coach_session_rows(
        db,
        [enrollment],
        coach_id=coach.id,
        from_date=date(2026, 10, 1),
        to_date=date(2026, 10, 31),
    )

    assert [row["session_date"] for row in rows] == ["2026-10-05", "2026-10-19"]


def test_reschedule_one_lesson_preserves_lesson_number_and_pin() -> None:
    db, coach, enrollment = _series_fixture()
    db.add(
        CourseSessionOverride(
            enrollment_id=enrollment.id,
            original_date=date(2026, 10, 12),
            action="rescheduled",
            rescheduled_start=datetime(2026, 10, 15, 14, 30),
            rescheduled_end=datetime(2026, 10, 15, 15, 30),
        )
    )
    db.commit()

    rows = build_coach_session_rows(
        db,
        [enrollment],
        coach_id=coach.id,
        from_date=date(2026, 10, 1),
        to_date=date(2026, 10, 31),
    )
    moved = next(row for row in rows if row["session_override"] == "rescheduled")

    assert moved["session_date"] == "2026-10-15"
    assert moved["original_session_date"] == "2026-10-12"
    assert moved["lesson_no"] == 2
    assert moved["checkin_pin"] == "10192"
