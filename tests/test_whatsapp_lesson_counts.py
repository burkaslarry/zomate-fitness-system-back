"""[F005][S003] WhatsApp lesson counts include paper 已上 for legacy packages."""

import json
from datetime import date, datetime, timedelta

from app.models import AuditLog, Branch, CategoryEnrollment, Coach, CourseCategory, CourseEnrollment, Student
from app.whatsapp_templates import whatsapp_lesson_counts


def test_whatsapp_lesson_counts_includes_category_prior(db_session):
    branch = Branch(name="TST", code="TST", address="Test")
    coach = Coach(full_name="Coach", phone="91230000", branch=branch, active=True)
    student = Student(full_name="Legacy", phone="91110002", branch=branch)
    category = CourseCategory(name="Renew 1-1", created_by_role="admin")
    db_session.add_all([branch, coach, student, category])
    db_session.flush()
    ledger = CategoryEnrollment(
        student_id=student.id,
        course_category_id=category.id,
        status="active",
        started_at=date.today(),
        total_lessons=20,
    )
    start = datetime.utcnow() + timedelta(days=1)
    enr = CourseEnrollment(
        title="續會學生一對一（舊 package）",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=student.id,
        scheduled_start=start,
        scheduled_end=start + timedelta(hours=1),
        checkin_pin="22222",
        total_lessons=10,
        legacy_category_enrollment_id=None,
    )
    db_session.add_all([ledger, enr])
    db_session.flush()
    enr.legacy_category_enrollment_id = ledger.id
    db_session.add(
        AuditLog(
            action="category_prior_lessons_import",
            student_id=student.id,
            detail=json.dumps({"enrollment_id": ledger.id, "delta": 8, "total_prior": 8}),
        )
    )
    db_session.commit()

    attended, remaining = whatsapp_lesson_counts(db_session, student.id, enr)
    assert attended == 8
    assert remaining == 10