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
        total_lessons=10, checkin_pin="10192", coach_time_confirmed=True,
    )
    db.add(enrollment)
    main.apply_lesson_ledger_delta(db, student, 10, "test_credit")
    db.commit()
    return student, coach, enrollment


@pytest.mark.parametrize("opted_in,has_coach,expected_keys", [
    (True, True, ["checkin_student", "checkin_coach"]),
    (False, True, ["checkin_coach"]),  # student opt-out skips student WA only
    (True, False, ["checkin_student"]),
])
def test_successful_checkin_notifies_only_expected_recipients(db_session, monkeypatch, opted_in, has_coach, expected_keys):
    """[F003][S003] Verify dynamic data, persisted attendance, consent and no duplicate send."""
    student, coach, enrollment = _checkin_data(db_session, opted_in)
    monkeypatch.setattr(main, "now_hk", lambda: datetime(2026, 10, 13, 10))
    captured = []
    if not has_coach:
        coach.phone = ""
        db_session.commit()

    def capture(phone, message, *, template_key=None, template_context=None):
        """[F003][S003] Assert attendance is already committed before any provider call."""
        assert db_session.query(Attendance).count() == 1
        assert main._lesson_balance_sum(db_session, student.id) == 9
        captured.append((phone, template_key, dict(template_context or {})))
        return type("R", (), {"ok": True, "dry_run": False, "message_id": "wamid.test", "error": None})()

    monkeypatch.setattr(main, "dispatch_reminder", capture)
    result, _ = main.perform_lesson_checkin(
        db_session, student, "qr_pin", resolved_enrollment=enrollment,
        notified_coach=coach if has_coach else None,
    )
    assert result["student"]["lesson_balance"] == 9
    assert [x[1] for x in captured] == expected_keys
    for phone, key, context in captured:
        if key == "checkin_student":
            assert phone == student.phone
        else:
            assert phone == coach.phone
        assert context["course_title"] == "Dynamic Pilates"
        assert context["student_name"] == "Student Example"
        if key == "checkin_student":
            # Per-package text (not a single ledger total).
            assert "Dynamic Pilates 剩9堂" in context["lesson_balance"]
            assert context["lessons_remaining"] == "9"
        else:
            # Coach sees remaining for the checked-in package only.
            assert context["lessons_remaining"] == "9"
            assert context["lesson_balance"] == "9"
            assert context["lessons_attended"] == "1"
    assert all(x.recipient != "coach-remind" for x in db_session.query(WhatsAppLog).all())
    with pytest.raises(HTTPException) as duplicate:
        main.perform_lesson_checkin(db_session, student, "qr_pin", resolved_enrollment=enrollment, notified_coach=coach)
    assert duplicate.value.status_code == 409
    assert len(captured) == len(expected_keys)
    assert main._lesson_balance_sum(db_session, student.id) == 9


def test_checkin_whatsapp_lists_each_package_remaining(db_session, monkeypatch):
    """[F003][S003] Student WA lists every package; coach WA uses the selected package only."""
    student, coach, enrollment = _checkin_data(db_session)
    other = CourseEnrollment(
        title="新學生一對一",
        student_id=student.id,
        coach_id=coach.id,
        branch_id=enrollment.branch_id,
        scheduled_start=datetime(2026, 10, 28, 10),
        scheduled_end=datetime(2026, 10, 28, 11),
        total_lessons=30,
        checkin_pin="20202",
        coach_time_confirmed=True,
    )
    db_session.add(other)
    main.apply_lesson_ledger_delta(db_session, student, 30, "test_credit_other")
    db_session.commit()
    monkeypatch.setattr(main, "now_hk", lambda: datetime(2026, 10, 13, 10))
    captured = []

    def capture(phone, message, *, template_key=None, template_context=None):
        captured.append((phone, template_key, message, dict(template_context or {})))
        return type("R", (), {"ok": True, "dry_run": False, "message_id": "wamid.test", "error": None})()

    monkeypatch.setattr(main, "dispatch_reminder", capture)
    main.perform_lesson_checkin(
        db_session, student, "qr_pin", resolved_enrollment=enrollment, notified_coach=coach
    )
    student_msg = next(m for _p, key, m, _c in captured if key == "checkin_student")
    coach_msg = next(m for _p, key, m, _c in captured if key == "checkin_coach")
    student_ctx = next(c for _p, key, _m, c in captured if key == "checkin_student")
    coach_ctx = next(c for _p, key, _m, c in captured if key == "checkin_coach")

    assert "各 package 剩餘堂數" in student_msg
    assert "Dynamic Pilates：剩 9 堂" in student_msg
    assert "新學生一對一：剩 30 堂" in student_msg
    assert "帳戶剩餘堂數" not in student_msg
    assert "Dynamic Pilates 剩9堂" in student_ctx["lesson_balance"]
    assert "新學生一對一 剩30堂" in student_ctx["lesson_balance"]

    assert "本課程剩餘堂數：9" in coach_msg
    assert "學生帳戶剩餘堂數" not in coach_msg
    assert coach_ctx["lessons_remaining"] == "9"
    assert coach_ctx["lesson_balance"] == "9"
    # Must not inject the other package's 30 into the coach remaining field.
    assert coach_ctx["lesson_balance"] != "39"


def test_checkin_does_not_notify_when_commit_fails(db_session, monkeypatch):
    """[F003][S003] A failed attendance write must not send a false success message."""
    student, coach, enrollment = _checkin_data(db_session)
    monkeypatch.setattr(main, "now_hk", lambda: datetime(2026, 10, 13, 10))
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
