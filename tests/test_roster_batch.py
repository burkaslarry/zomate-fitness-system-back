"""[F001][S003] Roster enrichment must stay flat as the page grows (no per-student query storm)."""

import json
from datetime import datetime

from sqlalchemy import event

from app import main
from app.models import Branch, CheckinLog, Coach, CourseEnrollment, LessonLedgerEntry, Student


def _seed(db, count: int = 12):
    branch = Branch(name="Sheung Wan", code="SW", address="Test")
    coach = Coach(full_name="Fung Lo", phone="91234567", branch=branch, active=True)
    db.add_all([branch, coach])
    db.flush()
    students = []
    for i in range(count):
        student = Student(
            full_name=f"Student {i}",
            phone=f"9111{i:04d}",
            branch=branch,
            hkid=f"S{i:03d}",
            health_notes=f"Coach: funglo / {coach.id}",
        )
        db.add(student)
        db.flush()
        db.add(LessonLedgerEntry(student_id=student.id, delta_lessons=10, reason="course_open_package"))
        db.add(CheckinLog(student_id=student.id, created_at=datetime(2026, 11, 1)))
        db.add(
            CourseEnrollment(
                title="Pilates",
                branch_id=branch.id,
                coach_id=coach.id,
                student_id=student.id,
                scheduled_start=datetime(2026, 11, 20, 10),
                scheduled_end=datetime(2026, 11, 20, 11),
                checkin_pin=f"1{i:04d}",
                total_lessons=10,
                coach_time_confirmed=True,
                segment_pins_json=json.dumps(
                    [{"installment_no": 1, "lesson_from": 1, "lesson_to": 10, "pin": f"1{i:04d}", "paid": True}]
                ),
            )
        )
        students.append(student)
    db.commit()
    return branch, coach, students


def test_roster_page_uses_constant_queries_and_keeps_fields(db_session):
    """[F001][S003] 12 students must cost a page-level query set, not ~10 queries each."""
    branch, coach, students = _seed(db_session)
    # Mirror the endpoint: rows arrive freshly loaded (commit expires instances, which would fake N+1).
    students = db_session.query(Student).order_by(Student.id).all()
    statements: list[str] = []
    engine = db_session.get_bind()

    def _record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _record)
    try:
        rows = main.student_to_member_dicts(db_session, students)
    finally:
        event.remove(engine, "before_cursor_execute", _record)

    assert len(rows) == 12
    assert len(statements) < 20
    first = rows[0]
    assert first["lesson_balance"] == 10
    assert first["is_active"] is True
    assert first["branch_code"] == "SW"
    assert first["current_course_package_status"] == "1 scheduled course(s)"
    assert first["onboarding_coach_id"] == coach.id
    assert first["onboarding_coach_name"] == coach.full_name
    assert first["display_name"].endswith("Student 0")
