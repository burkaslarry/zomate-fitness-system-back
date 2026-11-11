"""[F002][S003] Admin may split a category package into any number of uploadable periods."""

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app import main
from app.models import (
    AppUser,
    CategoryEnrollment,
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
