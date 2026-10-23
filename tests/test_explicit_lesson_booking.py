"""[F007][S005] Client SOP: every lesson needs an explicit coach appointment and one redemption."""
from datetime import date, datetime
import pytest
from fastapi import HTTPException
from app import main
from app.models import Attendance
from app.schemas import CoachBookSession
from test_same_day_booking import _fixture


def test_unconfirmed_placeholder_cannot_be_seen_or_redeemed(db_session, monkeypatch):
    """[F003][S002] A valid course PIN cannot turn an unconfirmed placeholder into attendance."""
    student, coach, enr, user = _fixture(db_session, monkeypatch)
    enr.scheduled_start = datetime(2026,10,23,15)
    enr.scheduled_end = datetime(2026,10,23,16)
    db_session.commit()
    assert main.public_student_today_lessons(student.id, db_session) == []
    assert main.resolve_checkin_pin_context(db_session, student, "10192") is None
    with pytest.raises(HTTPException):
        main.perform_lesson_checkin(db_session, student, "faceid", resolved_enrollment=enr)
    assert main._lesson_balance_sum(db_session, student.id) == 3
    assert db_session.query(Attendance).count() == 0


def test_first_lesson_locks_then_next_requires_new_coach_booking(db_session, monkeypatch):
    """[F003][S009] Completed lessons disappear; inferred weekly dates cannot unlock the next lesson."""
    student, coach, enr, user = _fixture(db_session, monkeypatch)
    main.coach_book_session(CoachBookSession(enrollment_id=enr.id, day=date(2026,10,23),
        start_hour=15, duration_hours=1), db_session, user)
    assert len(main.public_student_today_lessons(student.id, db_session)) == 1
    main.perform_lesson_checkin(db_session, student, "qr_pin", resolved_enrollment=enr, notified_coach=coach)
    assert main.public_student_today_lessons(student.id, db_session) == []
    assert main.resolve_checkin_pin_context(db_session, student, "10192") is None
    with pytest.raises(HTTPException) as locked:
        main._require_enrollment_session(db_session, user, enr.id, date(2026,10,23), coach.id)
    assert locked.value.status_code == 409
    monkeypatch.setattr(main, "now_hk", lambda: datetime(2026,10,30,15,5))
    assert main.resolve_checkin_pin_context(db_session, student, "10192") is None
    assert main.public_student_today_lessons(student.id, db_session) == []
    main.coach_book_session(CoachBookSession(enrollment_id=enr.id, day=date(2026,10,30),
        start_hour=15, duration_hours=1), db_session, user)
    assert len(main.public_student_today_lessons(student.id, db_session)) == 1
    assert main.resolve_checkin_pin_context(db_session, student, "10192")[0].id == enr.id
    main.perform_lesson_checkin(db_session, student, "qr_pin", resolved_enrollment=enr, notified_coach=coach)
    assert main._lesson_balance_sum(db_session, student.id) == 1
    assert main.public_student_today_lessons(student.id, db_session) == []
    assert db_session.query(Attendance).count() == 2
