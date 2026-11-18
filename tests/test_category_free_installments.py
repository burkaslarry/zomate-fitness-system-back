"""[F002][S003] Admin may split a category package into any number of uploadable periods."""

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app import main
from app.models import (
    AppUser,
    CategoryEnrollment,
    Coach,
    CourseCategory,
    InstallmentPayment,
    InstallmentPlan,
    Student,
)
from app.schemas import StudentCategoryEnrollmentCreate


def _seed(db):
    student = Student(full_name="Free Period Probe", phone="91110009")
    category = CourseCategory(name="Probe Category")
    db.add_all([student, category])
    db.commit()
    return student, category


def _admin():
    return AppUser(username="ops", role="ADMIN", password_salt="", password_hash="")


def _create(db, student, category, installments, lessons=20):
    payload = StudentCategoryEnrollmentCreate(
        course_category_id=category.id,
        total_lessons=lessons,
        total_installments=installments,
    )
    main.admin_upsert_category_enrollment(student.id, payload, db, _admin())
    enrollment = db.query(CategoryEnrollment).filter_by(student_id=student.id).one()
    plan = db.query(InstallmentPlan).filter_by(enrollment_id=enrollment.id).one()
    rows = (
        db.query(InstallmentPayment)
        .filter_by(installment_plan_id=plan.id)
        .order_by(InstallmentPayment.installment_no)
        .all()
    )
    return enrollment, plan, rows


def test_free_installment_count_seeds_one_upload_row_per_period(db_session):
    student, category = _seed(db_session)

    _, plan, rows = _create(db_session, student, category, 7)

    assert plan.total_installments == 7
    assert [r.installment_no for r in rows] == list(range(1, 8))
    assert all(r.paid_at is None and r.proof_receipt_id is None for r in rows)


def test_existing_unpaid_plan_resizes_both_ways(db_session):
    student, category = _seed(db_session)
    _create(db_session, student, category, 7)

    _, plan, rows = _create(db_session, student, category, 9)
    assert plan.total_installments == 9
    assert [r.installment_no for r in rows] == list(range(1, 10))

    _, plan, rows = _create(db_session, student, category, 4)
    assert plan.total_installments == 4
    assert [r.installment_no for r in rows] == [1, 2, 3, 4]


def test_resize_rejected_once_proof_is_uploaded(db_session):
    student, category = _seed(db_session)
    _, _, rows = _create(db_session, student, category, 5)
    rows[0].proof_receipt_id = 999
    db_session.commit()

    with pytest.raises(HTTPException) as exc:
        _create(db_session, student, category, 8)

    assert exc.value.status_code == 400
    assert "不可更改期數" in exc.value.detail


def test_installments_cannot_exceed_total_lessons():
    with pytest.raises(ValidationError):
        StudentCategoryEnrollmentCreate(
            course_category_id=1,
            total_lessons=10,
            total_installments=11,
        )


def test_imported_category_progress_is_scoped_and_not_a_course(db_session):
    """[F002][S003] Paper counts remain separate from unallocated debits and PIN courses."""
    student, category = _seed(db_session)
    other_category = CourseCategory(name="Other Category")
    coach = Coach(full_name="Fixture Coach", phone="91110010", active=True)
    db_session.add_all([other_category, coach])
    db_session.flush()
    admin = _admin()

    def save(category_id, total, prior):
        return main.admin_upsert_category_enrollment(
            student.id,
            StudentCategoryEnrollmentCreate(
                course_category_id=category_id, total_lessons=total,
                total_installments=3, lessons_already_taken=prior,
            ),
            db_session, admin,
        )

    saved = save(category.id, 30, 15)
    save(category.id, 30, 17)
    save(other_category.id, 12, 4)
    main.apply_lesson_ledger_delta(db_session, student, -1, "manual_unallocated")
    db_session.commit()

    full = main._member_full_payload(db_session, student)
    rows = {r["category_name"]: r for r in full["category_enrollments"]}
    assert rows[category.name]["id"] == saved["enrollment_id"]
    assert rows[category.name]["lessons_already_taken"] == 17
    assert rows[category.name]["remaining_from_paper"] == 13
    assert rows[other_category.name]["lessons_already_taken"] == 4
    assert rows[other_category.name]["remaining_from_paper"] == 8
    assert full["profile"]["lesson_balance"] == 20
    assert full["course_checkin_pins"] == []

    record = main.coach_student_records(student.id, coach.id, db_session, admin)
    by_name = {r.category_name: r for r in record.category_enrollments}
    assert by_name[category.name].lessons_already_taken == 17
    assert by_name[category.name].remaining_from_paper == 13
    assert by_name[other_category.name].lessons_already_taken == 4
    assert record.enrollments == []

    other_coach = AppUser(username="other", role="COACH", password_salt="", password_hash="", coach_id=coach.id)
    with pytest.raises(HTTPException) as exc:
        main.coach_student_records(student.id, coach.id, db_session, other_coach)
    assert exc.value.status_code == 403
