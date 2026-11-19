"""[F003][S007] Coach can schedule an imported paper ledger without double-crediting lessons."""

import json
from datetime import date, datetime, timedelta

import pytest

from app import main
from app.models import (
    AppUser,
    Attendance,
    AuditLog,
    Branch,
    CategoryEnrollment,
    Coach,
    CourseCategory,
    CourseEnrollment,
    Student,
)


def _seed(db):
    branch = Branch(name="TST", code="TST", address="Test")
    coach = Coach(full_name="Coach Fung", phone="91230000", branch=branch, active=True)
    student = Student(full_name="Paper Student", phone="91110001", branch=branch)
    category = CourseCategory(name="Yoga", created_by_role="admin")
    db.add_all([branch, coach, student, category])
    db.flush()
    ledger = CategoryEnrollment(
        student_id=student.id,
        course_category_id=category.id,
        status="active",
        started_at=date.today() - timedelta(days=60),
        total_lessons=30,
    )
    anchor = CourseEnrollment(
        title="Existing package",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=student.id,
        scheduled_start=datetime.combine(date.today() + timedelta(days=2), datetime.min.time()).replace(hour=9),
        scheduled_end=datetime.combine(date.today() + timedelta(days=2), datetime.min.time()).replace(hour=10),
        checkin_pin="11111",
        total_lessons=1,
        coach_time_confirmed=False,
    )
    db.add_all([ledger, anchor])
    db.flush()
    db.add(
        AuditLog(
            action="category_prior_lessons_import",
            student_id=student.id,
            detail=json.dumps({"enrollment_id": ledger.id, "delta": 15, "total_prior": 15}),
        )
    )
    db.commit()
    return branch, coach, student, ledger


def _coach_user(coach):
    return AppUser(
        username="fung",
        role="COACH",
        password_salt="",
        password_hash="",
        coach_id=coach.id,
    )


def test_coach_schedules_remaining_paper_lessons_once(db_session, monkeypatch):
    """[F003][S007] Conversion schedules 15 remaining lessons and keeps the paper count visible."""
    branch, coach, student, ledger = _seed(db_session)
    monkeypatch.setattr(main, "send_schedule_booking_whatsapp", lambda *a, **k: {"student": None, "coach": None})
    payload = main.CoachCategoryBooking(
        coach_id=coach.id,
        category_enrollment_id=ledger.id,
        day=date.today() + timedelta(days=3),
        start_hour=10,
        duration_hours=1,
    )

    out = main.coach_book_category_session(payload=payload, db=db_session, user=_coach_user(coach))

    assert out.total_lessons == 15
    created = db_session.get(CourseEnrollment, out.id)
    assert created is not None
    assert created.legacy_category_enrollment_id == ledger.id
    assert created.series_end_date is not None
    assert db_session.query(Attendance).filter(Attendance.course_id == out.id).count() == 0
    # No new credit and no extra debit: the category import already owns the ledger entries.
    assert main._lesson_balance_sum(db_session, student.id) == 0

    rec = main.coach_student_records(
        student_id=student.id, coach_id=coach.id, db=db_session, user=_coach_user(coach)
    )
    category = next(c for c in rec.category_enrollments if c.id == ledger.id)
    assert category.lessons_already_taken == 15
    assert category.remaining_from_paper == 15
    assert category.scheduled_enrollment_id == created.id
    legacy_course = next(e for e in rec.enrollments if e.enrollment_id == created.id)
    assert legacy_course.legacy_prior_lessons == 15

    roster = main.coach_list_students(coach_id=coach.id, db=db_session, user=_coach_user(coach))
    row = next(r for r in roster if r.student_id == student.id)
    category_row = next(c for c in row.category_packages if c.id == ledger.id)
    assert (category_row.lessons_already_taken, category_row.remaining_from_paper) == (15, 15)
    legacy_package = next(p for p in row.packages if p.enrollment_id == created.id)
    assert legacy_package.total_lessons == 15
    assert legacy_package.legacy_prior_lessons == 15

    with pytest.raises(main.HTTPException) as exc:
        main.coach_book_category_session(payload=payload, db=db_session, user=_coach_user(coach))
    assert exc.value.status_code == 409


def test_cancel_legacy_package_does_not_reverse_paper_ledger(db_session, monkeypatch):
    """[F003][S007] Cancel removes the course only; the category ledger and its paper counts stay."""
    _branch, coach, student, ledger = _seed(db_session)
    monkeypatch.setattr(main, "send_schedule_booking_whatsapp", lambda *a, **k: {"student": None, "coach": None})
    payload = main.CoachCategoryBooking(
        coach_id=coach.id,
        category_enrollment_id=ledger.id,
        day=date.today() + timedelta(days=3),
        start_hour=10,
        duration_hours=1,
    )
    out = main.coach_book_category_session(payload=payload, db=db_session, user=_coach_user(coach))

    result = main.coach_cancel_enrollment(
        enrollment_id=out.id,
        payload=main.CoachEnrollmentCancelBody(coach_id=coach.id),
        db=db_session,
        user=_coach_user(coach),
    )

    assert result["lessons_reversed"] == 0
    assert main._lesson_balance_sum(db_session, student.id) == 0
    rec = main.coach_student_records(
        student_id=student.id, coach_id=coach.id, db=db_session, user=_coach_user(coach)
    )
    category = next(c for c in rec.category_enrollments if c.id == ledger.id)
    assert category.lessons_already_taken == 15
    assert category.remaining_from_paper == 15
    assert category.scheduled_enrollment_id is None
    assert category.scheduled_once is True
