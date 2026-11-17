"""[F003][S005] Coach roster / student record expose installment periods and personal info."""

import json
from datetime import date, datetime

from app import main
from app.models import AppUser, Branch, Coach, CourseEnrollment, Receipt, Student


def _seed(db):
    branch = Branch(name="TST", code="TST", address="Test")
    coach = Coach(full_name="Coach Fung", phone="91230000", branch=branch, active=True)
    alice = Student(
        full_name="Alice Wong",
        phone="91110001",
        branch=branch,
        date_of_birth=date(1995, 4, 12),
        emergency_contact_name="Bob Wong",
        emergency_contact_relationship="Father",
        emergency_contact_phone="92220002",
    )
    db.add_all([branch, coach, alice])
    db.flush()
    segments = [
        {"installment_no": 1, "lesson_from": 1, "lesson_to": 10, "pin": "11111", "paid": True, "reminder_lesson": 9},
        {"installment_no": 2, "lesson_from": 11, "lesson_to": 20, "pin": "", "paid": False, "reminder_lesson": 19},
    ]
    enr1 = CourseEnrollment(
        title="Pilates",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=alice.id,
        scheduled_start=datetime(2026, 10, 6, 10),
        scheduled_end=datetime(2026, 10, 6, 11),
        checkin_pin="11111",
        total_lessons=20,
        coach_time_confirmed=True,
        segment_pins_json=json.dumps(segments),
        payment_state_json=json.dumps({"payments": {"installment:1": {"amount": 3000}}}),
    )
    enr2 = CourseEnrollment(
        title="Yoga 1:1",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=alice.id,
        scheduled_start=datetime(2026, 11, 6, 10),
        scheduled_end=datetime(2026, 11, 6, 11),
        checkin_pin="22222",
        total_lessons=10,
        coach_time_confirmed=False,
        segment_pins_json=json.dumps(
            [{"installment_no": 1, "lesson_from": 1, "lesson_to": 10, "pin": "22222", "paid": False}]
        ),
    )
    db.add_all([enr1, enr2])
    db.flush()
    return coach, alice, enr1, enr2


def test_coach_list_students_exposes_periods_and_next_installment(db_session):
    """[F003][S005] Roster packages carry 幾時扣堂 lesson ranges and the next unpaid period."""
    coach, alice, _enr1, _enr2 = _seed(db_session)
    admin = AppUser(username="ops", role="ADMIN", password_salt="", password_hash="")

    rows = main.coach_list_students(coach_id=coach.id, db=db_session, user=admin)
    assert len(rows) == 1
    row = rows[0]
    assert row.student_id == alice.id
    assert row.enrollment_count == 2
    by_title = {p.course_title: p for p in row.packages}
    pilates = by_title["Pilates"]
    assert [(p.installment_no, p.lesson_from, p.lesson_to, p.paid) for p in pilates.installment_periods] == [
        (1, 1, 10, True),
        (2, 11, 20, False),
    ]
    assert pilates.next_installment_no == 2
    assert pilates.next_reminder_lesson == 19
    yoga = by_title["Yoga 1:1"]
    assert yoga.next_installment_no == 1
    assert len(yoga.installment_periods) == 1


def test_coach_student_records_exposes_personal_info_and_periods(db_session):
    """[F003][S005] Student dossier includes DOB, emergency contact and per-enrollment periods."""
    coach, alice, _enr1, _enr2 = _seed(db_session)
    admin = AppUser(username="ops", role="ADMIN", password_salt="", password_hash="")

    rec = main.coach_student_records(student_id=alice.id, coach_id=coach.id, db=db_session, user=admin)
    assert rec.date_of_birth == date(1995, 4, 12)
    assert rec.emergency_contact_name == "Bob Wong"
    assert rec.emergency_contact_relationship == "Father"
    assert rec.emergency_contact_phone == "92220002"
    assert len(rec.enrollments) == 2
    by_title = {e.course_title: e for e in rec.enrollments}
    pilates = by_title["Pilates"]
    assert [(p.installment_no, p.lesson_from, p.lesson_to, p.paid) for p in pilates.installment_periods] == [
        (1, 1, 10, True),
        (2, 11, 20, False),
    ]
    assert pilates.next_installment_no == 2


def test_coach_student_records_lists_uploaded_receipts(db_session):
    """[F003][S005] Q4.2 — receipt files uploaded by coach/student are re-viewable."""
    coach, alice, _enr1, _enr2 = _seed(db_session)
    db_session.add(
        Receipt(
            student_id=alice.id,
            member_hkid="A123456",
            file_path="receipts/A123456/installment-2.png",
            amount=1000,
            payment_method="FPS",
            note="分期第2期",
            source="RENEWAL",
        )
    )
    db_session.commit()
    admin = AppUser(username="ops", role="ADMIN", password_salt="", password_hash="")

    rec = main.coach_student_records(student_id=alice.id, coach_id=coach.id, db=db_session, user=admin)
    assert len(rec.receipts) == 1
    assert rec.receipts[0].source == "RENEWAL"
    assert rec.receipts[0].amount == 1000
    assert rec.receipts[0].note == "分期第2期"
    assert rec.receipts[0].file_url.endswith("/uploads/receipts/A123456/installment-2.png")


def test_coach_can_cancel_own_pending_package(db_session):
    """[F003][S009] Q4/Q4.1 — COACH may cancel (soft-delete) their own pending package."""
    coach, _alice, _enr1, enr2 = _seed(db_session)
    coach_user = AppUser(
        username="fung",
        role="COACH",
        password_salt="",
        password_hash="",
        coach_id=coach.id,
    )

    result = main.coach_cancel_enrollment(
        enrollment_id=enr2.id,
        payload=main.CoachEnrollmentCancelBody(coach_id=coach.id),
        db=db_session,
        user=coach_user,
    )
    assert result["ok"] is True
    assert result["enrollment_id"] == enr2.id
    assert result["lessons_reversed"] == 10
    assert main._is_deleted(db_session, "course_enrollments", enr2.id)


def test_coach_cannot_cancel_other_coachs_package(db_session):
    """[F003][S009] A coach may only cancel packages assigned to their own profile."""
    coach, _alice, enr1, _enr2 = _seed(db_session)
    other = Coach(full_name="Other Coach", phone="91330000", active=True)
    db_session.add(other)
    db_session.flush()
    other_user = AppUser(
        username="other",
        role="COACH",
        password_salt="",
        password_hash="",
        coach_id=other.id,
    )
    try:
        main.coach_cancel_enrollment(
            enrollment_id=enr1.id,
            payload=main.CoachEnrollmentCancelBody(coach_id=coach.id),
            db=db_session,
            user=other_user,
        )
        raise AssertionError("expected HTTPException")
    except main.HTTPException as exc:
        assert exc.status_code == 403
