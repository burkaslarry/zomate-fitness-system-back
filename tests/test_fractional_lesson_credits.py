"""[F007][S002] Fractional ledger balance and duration-based check-in."""

from datetime import datetime

import pytest
from fastapi import HTTPException

from app import main
from app.lesson_credits import format_lesson_credits, quantize_lesson_credits
from app.models import Branch, Coach, CourseEnrollment, Student


def test_lesson_balance_shows_half_steps(db_session):
    branch = Branch(name="T", code="HALF", address="T", active=True)
    student = Student(full_name="Half Student", phone="90001111")
    db_session.add_all([branch, student])
    db_session.flush()
    main.apply_lesson_ledger_delta(db_session, student, 10, "seed")
    main.apply_lesson_ledger_delta(db_session, student, -0.5, "test")
    db_session.commit()
    assert main._lesson_balance_sum(db_session, student.id) == 9.5
    assert format_lesson_credits(9.5) == "9.5"


def test_checkin_deducts_slot_duration(db_session, monkeypatch):
    branch = Branch(name="T", code="DUR", address="T", active=True)
    coach = Coach(full_name="Coach", phone="+852 90000000", branch=branch, active=True)
    student = Student(full_name="Dur Student", phone="90002222")
    db_session.add_all([branch, coach, student])
    db_session.flush()
    enrollment = CourseEnrollment(
        title="Pilates",
        student_id=student.id,
        coach_id=coach.id,
        branch_id=branch.id,
        scheduled_start=datetime(2026, 10, 13, 10, 0),
        scheduled_end=datetime(2026, 10, 13, 11, 30),
        total_lessons=10,
        checkin_pin="10101",
        coach_time_confirmed=True,
    )
    db_session.add(enrollment)
    main.apply_lesson_ledger_delta(db_session, student, 10, "seed")
    db_session.commit()
    monkeypatch.setattr(main, "now_hk", lambda: datetime(2026, 10, 13, 10))
    main.perform_lesson_checkin(
        db_session, student, "qr_pin", resolved_enrollment=enrollment, notified_coach=coach
    )
    assert main._lesson_balance_sum(db_session, student.id) == 8.5
    with pytest.raises(HTTPException):
        main.perform_lesson_checkin(
            db_session, student, "qr_pin", resolved_enrollment=enrollment, notified_coach=coach
        )


def test_quantize_helpers():
    assert quantize_lesson_credits(9.3) == 9.5
    assert quantize_lesson_credits(9.76) == 10.0