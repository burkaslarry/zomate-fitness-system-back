"""[F003][S003] Check-in persistence, notification recipients and duplicate protection."""

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app import main
from app.models import Attendance, Branch, Coach, CourseEnrollment, Student, WhatsAppLog


def _checkin_data(db, opted_in=True):
    """[F003][S003] Isolate a course, coach and funded student in the test database."""
    branch = Branch(name="Test", code="NOTIFY", address="Test", active=True)
    coach = Coach(full_name="Coach Example", phone="+852 9123 4567", branch=branch, active=True)
    student = Student(full_name="Student Example", phone="93103031", whatsapp_reminder_opt_in=opted_in)
    db.add_all([branch, coach, student])
    db.flush()
    enrollment = CourseEnrollment(
        title="Dynamic Pilates", student_id=student.id, coach_id=coach.id, branch_id=branch.id,
        scheduled_start=datetime(2026, 10, 13, 10), scheduled_end=datetime(2026, 10, 13, 11),
        total_lessons=10, checkin_pin="10192",
    )
    db.add(enrollment)
    main.apply_lesson_ledger_delta(db, student, 10, "test_credit")
    db.commit()
    return student, coach, enrollment


@pytest.mark.parametrize("opted_in,has_coach,expected_keys", [
    (True, True, ["payment_student_pending", "payment_coach"]),
    (False, True, ["payment_coach"]),
    (True, False, ["payment_student_pending"]),
])
def test_successful_checkin_notifies_only_expected_recipients(db_session, monkeypatch, opted_in, has_coach, expected_keys):
    """[F003][S003] Verify dynamic data, persisted attendance, consent and no duplicate send."""
    student, coach, enrollment = _checkin_data(db_session, opted_in)
    captured = []
    if not has_coach:
        coach.phone = ""
        db_session.commit()

    def capture(phone, message, *, template_key, template_context):
        """[F003][S003] Assert attendance is already committed before any provider call."""
        assert db_session.query(Attendance).count() == 1
        assert main._lesson_balance_sum(db_session, student.id) == 9
        captured.append((phone, template_key, dict(template_context)))

    monkeypatch.setattr(main, "dispatch_reminder", capture)
    result, _ = main.perform_lesson_checkin(
        db_session, student, "qr_pin", resolved_enrollment=enrollment,
        notified_coach=coach if has_coach else None,
    )
    assert result["student"]["lesson_balance"] == 9
    assert [x[1] for x in captured] == expected_keys
    for phone, key, context in captured:
        assert phone == (student.phone if key.startswith("payment_student") else coach.phone)
        assert context["course_title"] == "Dynamic Pilates"
        assert context["student_name"] == "Student Example"
        assert context["lessons_remaining"] == "9"
        assert context["lessons_attended"] == "1"
    assert all(x.recipient != "coach-remind" for x in db_session.query(WhatsAppLog).all())
    with pytest.raises(HTTPException) as duplicate:
        main.perform_lesson_checkin(db_session, student, "qr_pin", resolved_enrollment=enrollment, notified_coach=coach)
    assert duplicate.value.status_code == 409
    assert len(captured) == len(expected_keys)
    assert main._lesson_balance_sum(db_session, student.id) == 9


def test_checkin_does_not_notify_when_commit_fails(db_session, monkeypatch):
    """[F003][S003] A failed attendance write must not send a false success message."""
    student, coach, enrollment = _checkin_data(db_session)
    captured = []

    def capture(*args, **kwargs):
        """[F003][S003] Record any unexpected provider call."""
        captured.append(args)

    def fail_commit():
        """[F003][S003] Simulate database failure before the notification block."""
        raise RuntimeError("Simulated storage failure")

    monkeypatch.setattr(main, "dispatch_reminder", capture)
    monkeypatch.setattr(db_session, "commit", fail_commit)
    with pytest.raises(RuntimeError, match="storage failure"):
        main.perform_lesson_checkin(db_session, student, "qr_pin", resolved_enrollment=enrollment, notified_coach=coach)
    assert captured == []
    db_session.rollback()
    assert db_session.query(Attendance).count() == 0
    assert main._lesson_balance_sum(db_session, student.id) == 10
