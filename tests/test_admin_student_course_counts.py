"""[F004][S002] Admin sees per-course 已上／剩 when one student holds concurrent courses."""

from datetime import date, datetime

from app import main
from app.models import Attendance, Branch, Coach, CourseEnrollment, Student


def _seed(db):
    branch = Branch(name="TST", code="TST", address="Test")
    coach = Coach(full_name="Coach Fung", phone="91230000", branch=branch, active=True)
    alice = Student(full_name="Alice Wong", phone="91110001", branch=branch)
    db.add_all([branch, coach, alice])
    db.flush()
    one_to_one = CourseEnrollment(
        title="1:1",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=alice.id,
        scheduled_start=datetime(2026, 12, 1, 10),
        scheduled_end=datetime(2026, 12, 1, 11),
        checkin_pin="11111",
        total_lessons=20,
        coach_time_confirmed=True,
    )
    yoga = CourseEnrollment(
        title="Yoga",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=alice.id,
        scheduled_start=datetime(2026, 12, 15, 12),
        scheduled_end=datetime(2026, 12, 15, 13),
        checkin_pin="22222",
        total_lessons=10,
        coach_time_confirmed=True,
    )
    db.add_all([one_to_one, yoga])
    db.flush()
    for enr in [one_to_one] * 6 + [yoga] * 2:
        db.add(
            Attendance(
                student_id=alice.id,
                course_id=enr.id,
                coach_id=coach.id,
                branch_id=branch.id,
                attended_at=datetime(2026, 11, 1, 10),
                session_calendar_date=date(2026, 11, 1),
            )
        )
    db.commit()
    return alice, one_to_one, yoga


def test_member_full_shows_per_course_attendance(db_session):
    alice, one_to_one, yoga = _seed(db_session)
    payload = main._member_full_payload(db_session, alice)
    by_course = {r["course_id"]: r for r in payload["course_checkin_pins"]}
    assert by_course[one_to_one.id]["lessons_attended"] == 6
    assert by_course[yoga.id]["lessons_attended"] == 2
    assert (
        by_course[one_to_one.id]["total_lessons"]
        - by_course[one_to_one.id]["lessons_attended"]
    ) == 14
    assert (
        by_course[yoga.id]["total_lessons"]
        - by_course[yoga.id]["lessons_attended"]
    ) == 8
