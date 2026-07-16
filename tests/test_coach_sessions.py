"""[F008][S002] Unit tests for coach session row builder."""

from datetime import date, datetime

from app.coach_sessions import build_coach_session_rows, resolve_enrollment_category
from app.main import _coach_payment_summary
from app.models import Branch, Coach, CourseCategory, CourseEnrollment, RenewalRecord, Student


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


def test_build_coach_session_rows_skips_unresolved_category(db_session):
    """[F008][S004] Enrollments without a course category must not appear in coach reports."""
    branch = Branch(name="TST", code="TST5", address="a", active=True)
    coach = Coach(full_name="C3", phone="90000004", branch=branch, active=True)
    student = Student(full_name="Larry Lo, Pilates E2E 774413", phone="93333333", hkid="A333")
    db_session.add_all([branch, coach, student])
    db_session.flush()

    enr = CourseEnrollment(
        title="Pilates E2E 774413",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=student.id,
        scheduled_start=datetime(2026, 7, 5, 10, 0),
        scheduled_end=datetime(2026, 7, 5, 11, 0),
        total_lessons=8,
        lesson_weekdays="5",
        series_start_date=date(2026, 7, 5),
        series_end_date=date(2026, 7, 31),
        checkin_pin="77441",
        coach_time_confirmed=True,
    )
    db_session.add(enr)
    db_session.commit()

    rows = build_coach_session_rows(
        db_session,
        [enr],
        coach_id=coach.id,
        from_date=date(2026, 7, 1),
        to_date=date(2026, 7, 31),
    )
    assert rows == []


def test_coach_payment_summary_pending_without_receipt(db_session):
    """[F003][S003] Open-package enrollment without receipt must not read as Paid."""
    branch = Branch(name="TST", code="TST4", address="a", active=True)
    coach = Coach(full_name="Fung Lo", phone="90008888", branch=branch, active=True)
    student = Student(full_name="Wai Lun, Lo", phone="93103035", hkid="Y011")
    db_session.add_all([branch, coach, student])
    db_session.flush()

    enr = CourseEnrollment(
        title="Yoga",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=student.id,
        scheduled_start=datetime(2026, 7, 16, 10, 0),
        scheduled_end=datetime(2026, 7, 16, 11, 0),
        total_lessons=10,
        checkin_pin="95398",
        segment_pins_json=None,
        coach_time_confirmed=True,
    )
    db_session.add(enr)
    db_session.add(
        RenewalRecord(
            student_id=student.id,
            student_name=student.full_name,
            phone=student.phone,
            course_ratio="1-1",
            lessons=10,
            payment_method="cash",
            coach_id=coach.id,
            amount=8000,
            receipt_id=None,
            applicant_name=student.full_name,
            signature="sig",
            renewal_date=date(2026, 7, 16),
        )
    )
    db_session.commit()

    pay_st, inst_st, _, _ = _coach_payment_summary(db_session, enr, student)
    assert pay_st == "Pending"
    assert inst_st == "待補收據"
