"""[F008][S002] Unit tests for coach session row builder."""

from datetime import date, datetime

from app.coach_sessions import build_coach_session_rows, resolve_enrollment_category
from app.models import Branch, Coach, CourseCategory, CourseEnrollment, Student


def test_resolve_enrollment_category_from_title(db_session):
    branch = Branch(name="TST", code="TST2", address="a", active=True)
    coach = Coach(full_name="C", phone="90000002", branch=branch, active=True)
    cat = CourseCategory(name="泰拳一對一", is_active=True, is_deleted=False, created_by_role="test")
    student = Student(full_name="S", phone="91111111", hkid="A111")
    db_session.add_all([branch, coach, cat, student])
    db_session.flush()

    enr = CourseEnrollment(
        title="泰拳一對一 · S",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=student.id,
        scheduled_start=datetime(2026, 6, 1, 10, 0),
        scheduled_end=datetime(2026, 6, 1, 11, 0),
        total_lessons=1,
        checkin_pin="12345",
    )
    db_session.add(enr)
    db_session.commit()

    cid, name = resolve_enrollment_category(db_session, enr)
    assert cid == cat.id
    assert name == "泰拳一對一"


def test_build_coach_session_rows_single_day(db_session):
    branch = Branch(name="TST", code="TST3", address="a", active=True)
    coach = Coach(full_name="C2", phone="90000003", branch=branch, active=True)
    cat = CourseCategory(name="新學生一對一", is_active=True, is_deleted=False, created_by_role="test")
    student = Student(full_name="Lee", phone="92222222", hkid="A222")
    db_session.add_all([branch, coach, cat, student])
    db_session.flush()

    enr = CourseEnrollment(
        title="新學生一對一 · Lee",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=student.id,
        scheduled_start=datetime(2026, 7, 10, 10, 0),
        scheduled_end=datetime(2026, 7, 10, 11, 0),
        total_lessons=1,
        checkin_pin="54321",
        coach_time_confirmed=True,
    )
    db_session.add(enr)
    db_session.commit()

    rows = build_coach_session_rows(
        db_session,
        [enr],
        coach_id=coach.id,
        day=date(2026, 7, 10),
    )
    assert len(rows) == 1
    assert rows[0]["student_name"] == "Lee"
    assert rows[0]["category_name"] == "新學生一對一"
    assert rows[0]["attendance_status"] == "未簽到"
