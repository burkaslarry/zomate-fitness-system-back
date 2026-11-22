"""[F002][S003] Admin may split a category package into any number of uploadable periods."""

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app import main
from app.models import (
    AppUser,
    Branch,
    CategoryEnrollment,
    Coach,
    CourseCategory,
    CourseEnrollment,
    InstallmentPayment,
    InstallmentPlan,
    Student,
)
from app.schemas import StudentCategoryEnrollmentCreate


def _seed(db):
    branch = Branch(name="TST", code="TST", address="Test")
    coach = Coach(full_name="Fixture Coach", phone="91110010", branch=branch, active=True)
    student = Student(full_name="Free Period Probe", phone="91110009", branch=branch)
    category = CourseCategory(name="Probe Category")
    db.add_all([branch, coach, student, category])
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
    result = main.admin_upsert_category_enrollment(student.id, payload, db, _admin())
    enrollment = db.query(CategoryEnrollment).filter_by(student_id=student.id).one()
    plan = db.query(InstallmentPlan).filter_by(enrollment_id=enrollment.id).one()
    rows = (
        db.query(InstallmentPayment)
        .filter_by(installment_plan_id=plan.id)
        .order_by(InstallmentPayment.installment_no)
        .all()
    )
    return enrollment, plan, rows, result


def test_free_installment_count_seeds_one_upload_row_per_period(db_session):
    student, category = _seed(db_session)

    _, plan, rows, result = _create(db_session, student, category, 7)

    assert plan.total_installments == 7
    assert [r.installment_no for r in rows] == list(range(1, 8))
    assert all(r.paid_at is None and r.proof_receipt_id is None for r in rows)
    pin = result["checkin_pin"]
    assert pin and pin.isdigit() and len(pin) == 5
    assert result["course_enrollment_id"]


def test_existing_unpaid_plan_resizes_both_ways(db_session):
    student, category = _seed(db_session)
    _create(db_session, student, category, 7)

    _, plan, rows, _ = _create(db_session, student, category, 9)
    assert plan.total_installments == 9
    assert [r.installment_no for r in rows] == list(range(1, 10))

    _, plan, rows, result = _create(db_session, student, category, 4)
    assert plan.total_installments == 4
    assert [r.installment_no for r in rows] == [1, 2, 3, 4]
    assert result["checkin_pin"] and len(result["checkin_pin"]) == 5


def test_resize_rejected_once_proof_is_uploaded(db_session):
    student, category = _seed(db_session)
    _, _, rows, _ = _create(db_session, student, category, 5)
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


def test_upsert_returns_five_digit_pin_without_marking_paid(db_session, monkeypatch):
    """[F004][S002] Saving a paid old package creates a PIN shell; confirm still owns WhatsApp."""
    student, category = _seed(db_session)
    sent = []
    monkeypatch.setattr(
        main,
        "send_payment_whatsapp_notifications",
        lambda *a, **k: sent.append(k) or {"pin_unlocked": "—"},
    )

    created = main.admin_upsert_category_enrollment(
        student.id,
        StudentCategoryEnrollmentCreate(
            course_category_id=category.id,
            total_lessons=20,
            total_installments=3,
            lessons_already_taken=5,
        ),
        db_session,
        _admin(),
    )
    pin = created["checkin_pin"]
    assert pin and pin.isdigit() and len(pin) == 5
    shell = db_session.get(CourseEnrollment, created["course_enrollment_id"])
    assert shell is not None
    assert shell.legacy_category_enrollment_id == created["enrollment_id"]
    assert shell.checkin_pin == pin
    assert shell.coach_time_confirmed is False

    plan = db_session.query(InstallmentPlan).filter_by(enrollment_id=created["enrollment_id"]).one()
    pays = (
        db_session.query(InstallmentPayment)
        .filter_by(installment_plan_id=plan.id)
        .all()
    )
    assert all(p.paid_at is None for p in pays)
    assert sent == []

    updated = main.admin_upsert_category_enrollment(
        student.id,
        StudentCategoryEnrollmentCreate(
            course_category_id=category.id,
            total_lessons=20,
            total_installments=3,
            lessons_already_taken=5,
        ),
        db_session,
        _admin(),
    )
    assert updated["course_enrollment_id"] == created["course_enrollment_id"]
    assert updated["checkin_pin"] == pin


def test_imported_category_progress_is_scoped_and_not_a_course(db_session):
    """[F002][S003] Paper counts remain separate from unallocated debits; PIN shells stay unscheduled."""
    student, category = _seed(db_session)
    other_category = CourseCategory(name="Other Category")
    coach = db_session.query(Coach).first()
    db_session.add(other_category)
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
    # PIN shells exist after upsert, but they are not coach-confirmed schedules.
    assert len(full["course_checkin_pins"]) == 2
    assert all(r["checkin_pin"] and len(r["checkin_pin"]) == 5 for r in full["course_checkin_pins"])

    record = main.coach_student_records(student.id, coach.id, db_session, admin)
    by_name = {r.category_name: r for r in record.category_enrollments}
    assert by_name[category.name].lessons_already_taken == 17
    assert by_name[category.name].remaining_from_paper == 13
    assert by_name[other_category.name].lessons_already_taken == 4
    assert by_name[category.name].scheduled_enrollment_id is None
    assert all(not e.coach_time_confirmed for e in record.enrollments)

    outsider = Coach(full_name="Other Coach", phone="91110011", branch=coach.branch, active=True)
    db_session.add(outsider)
    db_session.flush()
    other_coach = AppUser(
        username="other", role="COACH", password_salt="", password_hash="", coach_id=outsider.id
    )
    with pytest.raises(HTTPException) as exc:
        main.coach_student_records(student.id, outsider.id, db_session, other_coach)
    assert exc.value.status_code == 403
