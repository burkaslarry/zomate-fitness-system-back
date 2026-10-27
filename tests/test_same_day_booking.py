"""[F007][S005] Same-day staff booking through real scheduling/PIN/check-in logic, isolated DB."""
from datetime import date, datetime

import pytest
from fastapi import HTTPException

from app import main
from app.models import AppUser, Attendance, Branch, Coach, CourseEnrollment, Student
from app.schemas import CoachBookSession, CoachScheduleConfirm


def _fixture(db, monkeypatch):
    """[F007][S005] Freeze HKT and suppress provider calls without bypassing policy checks."""
    monkeypatch.setattr(main, "now_hk", lambda: datetime(2026, 10, 23, 15, 5))
    monkeypatch.setattr(main, "send_payment_whatsapp_notifications", lambda *a, **k: None)
    monkeypatch.setattr(main, "dispatch_reminder", lambda *a, **k: None)
    branch = Branch(name="QA", code="SAMEDAY", address="QA", active=True)
    coach = Coach(full_name="QA Coach", phone="90000001", branch=branch, active=True)
    student = Student(full_name="QA Student", phone="90000002", whatsapp_reminder_opt_in=False)
    db.add_all([branch, coach, student]); db.flush()
    enr = CourseEnrollment(title="QA same-day", branch_id=branch.id, coach_id=coach.id,
        student_id=student.id, scheduled_start=datetime(2026, 11, 2, 15),
        scheduled_end=datetime(2026, 11, 2, 16), total_lessons=3,
        checkin_pin="10192", coach_time_confirmed=False)
    db.add(enr)
    main.apply_lesson_ledger_delta(db, student, 3, "test_credit")
    db.commit()
    user = AppUser(username="qa-coach", role="COACH", coach_id=coach.id, is_active=True)
    return student, coach, enr, user


@pytest.mark.parametrize("route", ["book", "confirm"])
def test_same_day_booking_resolves_pin_and_debits_once(db_session, monkeypatch, route):
    """[F003][S004] Both initial routes allow an ongoing lesson and preserve duplicate protection."""
    student, coach, enr, user = _fixture(db_session, monkeypatch)
    args = dict(enrollment_id=enr.id, day=date(2026, 10, 23), start_hour=15,
                start_minute=0, duration_hours=1)
    if route == "book":
        main.coach_book_session(CoachBookSession(**args), db_session, user)
    else:
        main.coach_confirm_enrollment_schedule(enr.id, CoachScheduleConfirm(**args), db_session, user)
    resolved = main.resolve_checkin_pin_context(db_session, student, "10192")
    assert resolved and resolved[0].id == enr.id
    assert enr.scheduled_start == datetime(2026, 10, 23, 15)
    main.perform_lesson_checkin(db_session, student, "qr_pin", resolved_enrollment=enr, notified_coach=coach)
    assert main._lesson_balance_sum(db_session, student.id) == 2
    with pytest.raises(HTTPException) as exc:
        main.perform_lesson_checkin(db_session, student, "qr_pin", resolved_enrollment=enr, notified_coach=coach)
    assert exc.value.status_code == 409
    assert db_session.query(Attendance).count() == 1
    assert main._lesson_balance_sum(db_session, student.id) == 2


@pytest.mark.parametrize("day,hour", [(date(2026, 10, 22), 15), (date(2026, 10, 23), 14)])
def test_ended_or_past_bookings_rejected(db_session, monkeypatch, day, hour):
    """[F003][S004] No historical attendance can be manufactured by booking ended slots."""
    _, _, enr, user = _fixture(db_session, monkeypatch)
    with pytest.raises(HTTPException) as exc:
        main.coach_book_session(CoachBookSession(enrollment_id=enr.id, day=day,
            start_hour=hour, start_minute=0, duration_hours=1), db_session, user)
    assert exc.value.status_code == 400
    assert not enr.coach_time_confirmed


def test_permission_conflict_and_reconfirmation_rejected(db_session, monkeypatch):
    """[F003][S004] Same-day exception cannot cross coach ownership or overwrite a series."""
    _, _, enr, user = _fixture(db_session, monkeypatch)
    args = dict(enrollment_id=enr.id, day=date(2026, 10, 23), start_hour=15,
                start_minute=0, duration_hours=1)
    original = user.coach_id
    user.coach_id = 99999
    user.username = "unlinked-user"
    with pytest.raises(HTTPException) as exc:
        main.coach_book_session(CoachBookSession(**args), db_session, user)
    assert exc.value.status_code == 403
    user.coach_id = original
    user.username = "qa-coach"
    conflict = CourseEnrollment(title="Occupied", student_id=enr.student_id,
        coach_id=enr.coach_id, branch_id=enr.branch_id, scheduled_start=datetime(2026, 10, 23, 15),
        scheduled_end=datetime(2026, 10, 23, 16), total_lessons=1, checkin_pin="20202", lesson_weekdays="4",
        series_start_date=date(2026, 10, 23), series_end_date=date(2026, 10, 23), coach_time_confirmed=True)
    db_session.add(conflict); db_session.commit()
    with pytest.raises(HTTPException) as exc:
        main.coach_book_session(CoachBookSession(**args), db_session, user)
    assert exc.value.status_code == 409
    enr.coach_time_confirmed = True
    with pytest.raises(HTTPException) as exc:
        main.coach_confirm_enrollment_schedule(enr.id, CoachScheduleConfirm(**args), db_session, user)
    assert exc.value.status_code == 400


def test_reschedule_notices_still_enforced(monkeypatch):
    """[F003][S004] Admin keeps 24h; coach may change until lesson start."""
    monkeypatch.setattr(main, "now_hk", lambda: datetime(2026, 10, 23, 15, 5))
    with pytest.raises(HTTPException) as exc:
        main._assert_change_notice(datetime(2026, 10, 23, 16))
    assert exc.value.status_code == 400
    # Coach: still before start → allowed
    main._assert_change_notice(datetime(2026, 10, 23, 16), actor_role="COACH")
    # Coach: at/after start → blocked
    with pytest.raises(HTTPException) as coach_exc:
        main._assert_change_notice(datetime(2026, 10, 23, 15, 5), actor_role="COACH")
    assert coach_exc.value.status_code == 400
    with pytest.raises(HTTPException):
        main._assert_initial_staff_booking(datetime(2026, 10, 23, 14), datetime(2026, 10, 23, 15, 5))
