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


def test_coach_booking_attaches_schedule_to_admin_confirm_pin_shell(db_session, monkeypatch):
    """[F004][S002] Admin confirm PIN shell must not 409 forever; booking updates that shell."""
    _branch, coach, student, ledger = _seed(db_session)
    monkeypatch.setattr(main, "send_schedule_booking_whatsapp", lambda *a, **k: {"student": None, "coach": None})
    shell = main._ensure_legacy_category_course_enrollment(db_session, ledger, student)
    db_session.commit()
    assert shell.coach_time_confirmed is False
    pin_before = shell.checkin_pin

    rec_before = main.coach_student_records(
        student_id=student.id, coach_id=coach.id, db=db_session, user=_coach_user(coach)
    )
    category_before = next(c for c in rec_before.category_enrollments if c.id == ledger.id)
    assert category_before.scheduled_enrollment_id is None
    assert category_before.scheduled_once is False

    payload = main.CoachCategoryBooking(
        coach_id=coach.id,
        category_enrollment_id=ledger.id,
        day=date.today() + timedelta(days=3),
        start_hour=10,
        duration_hours=1,
    )
    out = main.coach_book_category_session(payload=payload, db=db_session, user=_coach_user(coach))

    assert out.id == shell.id
    updated = db_session.get(CourseEnrollment, shell.id)
    assert updated.coach_time_confirmed is True
    assert updated.checkin_pin == pin_before
    assert updated.total_lessons == 15

    with pytest.raises(main.HTTPException) as exc:
        main.coach_book_category_session(payload=payload, db=db_session, user=_coach_user(coach))
    assert exc.value.status_code == 409


def test_legacy_shell_total_resyncs_after_prior_update(db_session):
    """[F004][S002] Shell total_lessons stays remaining-only when 以上堂數 changes (10→8, not 12 in UI)."""
    branch = Branch(name="TST", code="TST", address="Test")
    coach = Coach(full_name="Coach Fung", phone="91230000", branch=branch, active=True)
    student = Student(full_name="Yeung Case", phone="91112222", branch=branch)
    category = CourseCategory(name="續會學生一對一", created_by_role="admin")
    db_session.add_all([branch, coach, student, category])
    db_session.commit()
    admin = AppUser(username="ops", role="ADMIN", password_salt="", password_hash="")

    first = main.admin_upsert_category_enrollment(
        student.id,
        main.StudentCategoryEnrollmentCreate(
            course_category_id=category.id,
            total_lessons=10,
            total_installments=1,
            lessons_already_taken=0,
        ),
        db_session,
        admin,
    )
    shell = db_session.get(CourseEnrollment, first["course_enrollment_id"])
    assert shell is not None
    assert shell.total_lessons == 10

    main.admin_upsert_category_enrollment(
        student.id,
        main.StudentCategoryEnrollmentCreate(
            course_category_id=category.id,
            total_lessons=10,
            total_installments=1,
            lessons_already_taken=2,
        ),
        db_session,
        admin,
    )
    db_session.refresh(shell)
    assert shell.total_lessons == 8

    rec = main.coach_student_records(
        student_id=student.id, coach_id=coach.id, db=db_session, user=_coach_user(coach)
    )
    enr = next(e for e in rec.enrollments if e.enrollment_id == shell.id)
    assert enr.total_lessons == 8
    assert enr.legacy_prior_lessons == 2
    assert enr.legacy_category_enrollment_id == first["enrollment_id"]
    # [F003][S007] Ledger still listed for dossier, but picker should skip it via linked id.
    assert any(c.id == first["enrollment_id"] for c in rec.category_enrollments)


def test_coach_booking_attaches_to_upsert_pin_shell(db_session, monkeypatch):
    """[F004][S002] Coach booking reuses the PIN shell created when Admin imports/saves the package."""
    branch = Branch(name="SW", code="SW", address="Test")
    coach = Coach(full_name="Coach Lee", phone="91230099", branch=branch, active=True)
    student = Student(full_name="Upsert Shell Student", phone="91119999", branch=branch)
    category = CourseCategory(name="Pilates Pack", created_by_role="admin")
    db_session.add_all([branch, coach, student, category])
    db_session.commit()
    monkeypatch.setattr(main, "send_schedule_booking_whatsapp", lambda *a, **k: {"student": None, "coach": None})

    saved = main.admin_upsert_category_enrollment(
        student.id,
        main.StudentCategoryEnrollmentCreate(
            course_category_id=category.id,
            total_lessons=20,
            total_installments=2,
            lessons_already_taken=5,
        ),
        db_session,
        AppUser(username="ops", role="ADMIN", password_salt="", password_hash=""),
    )
    shell_id = saved["course_enrollment_id"]
    pin_before = saved["checkin_pin"]
    assert shell_id and pin_before and len(pin_before) == 5

    payload = main.CoachCategoryBooking(
        coach_id=coach.id,
        category_enrollment_id=saved["enrollment_id"],
        day=date.today() + timedelta(days=3),
        start_hour=11,
        duration_hours=1,
    )
    out = main.coach_book_category_session(payload=payload, db=db_session, user=_coach_user(coach))

    assert out.id == shell_id
    updated = db_session.get(CourseEnrollment, shell_id)
    assert updated.coach_time_confirmed is True
    assert updated.checkin_pin == pin_before
    assert updated.total_lessons == 15
    assert updated.legacy_category_enrollment_id == saved["enrollment_id"]
