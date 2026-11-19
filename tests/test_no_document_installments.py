"""[F004][S002] 「唔需要上傳文件」 tick per installment period (course + category)."""

import json
from datetime import date, datetime

import pytest

from app import main
from app.models import (
    AppUser,
    Attendance,
    Branch,
    CategoryEnrollment,
    Coach,
    CourseCategory,
    CourseEnrollment,
    InstallmentPayment,
    InstallmentPlan,
    Student,
)
from fastapi import HTTPException


def _seed(db):
    branch = Branch(name="TST", code="TST", address="Test")
    coach = Coach(full_name="Coach Fung", phone="91230000", branch=branch, active=True)
    alice = Student(full_name="Alice Wong", phone="91110001", branch=branch)
    db.add_all([branch, coach, alice])
    db.flush()
    enrollment = CourseEnrollment(
        title="Pilates",
        branch_id=branch.id,
        coach_id=coach.id,
        student_id=alice.id,
        scheduled_start=datetime(2026, 10, 6, 10),
        scheduled_end=datetime(2026, 10, 6, 11),
        checkin_pin="11111",
        total_lessons=30,
        segment_pins_json=json.dumps(
            [
                {"installment_no": 1, "lesson_from": 1, "lesson_to": 10, "pin": "11111", "paid": True, "amount_hkd": 3000},
                {"installment_no": 2, "lesson_from": 11, "lesson_to": 20, "pin": "", "paid": False, "amount_hkd": 3000},
                {"installment_no": 3, "lesson_from": 21, "lesson_to": 30, "pin": "", "paid": False},
            ]
        ),
        payment_state_json=json.dumps({"payments": {"installment:1": {"amount": 3000}}}),
    )
    db.add(enrollment)
    db.flush()
    category = CourseCategory(name="Yoga")
    db.add(category)
    db.flush()
    cat_enrollment = CategoryEnrollment(
        student_id=alice.id,
        course_category_id=category.id,
        started_at=date(2026, 10, 1),
        total_lessons=10,
    )
    db.add(cat_enrollment)
    db.flush()
    plan = InstallmentPlan(enrollment_id=cat_enrollment.id, total_installments=2, status="active")
    db.add(plan)
    db.flush()
    db.add_all(
        [
            InstallmentPayment(
                installment_plan_id=plan.id,
                installment_no=1,
                amount=1000,
                due_date=date(2026, 10, 1),
                paid_at=datetime(2026, 10, 2),
                status="paid",
            ),
            InstallmentPayment(
                installment_plan_id=plan.id,
                installment_no=2,
                amount=1000,
                due_date=date(2026, 11, 1),
                status="pending",
            ),
        ]
    )
    db.commit()
    return alice, enrollment, plan


@pytest.fixture
def admin():
    return AppUser(username="ops", role="ADMIN", password_salt="", password_hash="")


def test_course_confirm_without_upload_rejected_until_no_upload_ticked(db_session, monkeypatch, admin):
    """[F004][S002] Pending-proof rule still blocks plain confirms; the tick authorizes them."""
    alice, enrollment, _plan = _seed(db_session)
    monkeypatch.setattr(main, "send_payment_whatsapp_notifications", lambda *args, **kwargs: {})
    from app.schemas import CourseInstallmentNoUpload

    with pytest.raises(HTTPException) as exc:
        main.admin_course_mark_installment_paid(
            enrollment.id,
            main.CourseInstallmentMarkPaid(student_id=alice.id, installment_no=2),
            db=db_session,
            user=admin,
        )
    assert exc.value.status_code == 400

    main.admin_course_set_installment_no_upload(
        enrollment.id,
        CourseInstallmentNoUpload(student_id=alice.id, installment_no=2, no_upload=True),
        db=db_session,
        user=admin,
    )
    db_session.expire_all()
    enr = db_session.query(CourseEnrollment).filter(CourseEnrollment.id == enrollment.id).first()
    assert main._course_no_upload_nos(enr) == {2}

    out = main.admin_course_mark_installment_paid(
        enrollment.id,
        main.CourseInstallmentMarkPaid(student_id=alice.id, installment_no=2),
        db=db_session,
        user=admin,
    )
    segment = next(
        s for s in out.enrollments[0].installment_segments if s.installment_no == 2
    )
    assert segment.paid is True
    assert segment.pin != ""  # [F003][S002] PIN issued on confirmed payment


def test_course_no_upload_toggle_off(db_session, admin):
    """[F004][S002] Unticking restores the uploaded-proof requirement."""
    _alice, enrollment, _plan = _seed(db_session)
    from app.schemas import CourseInstallmentNoUpload

    main.admin_course_set_installment_no_upload(
        enrollment.id,
        CourseInstallmentNoUpload(student_id=enrollment.student_id, installment_no=2, no_upload=True),
        db=db_session,
        user=admin,
    )
    main.admin_course_set_installment_no_upload(
        enrollment.id,
        CourseInstallmentNoUpload(student_id=enrollment.student_id, installment_no=2, no_upload=False),
        db=db_session,
        user=admin,
    )
    db_session.expire_all()
    enr = db_session.query(CourseEnrollment).filter(CourseEnrollment.id == enrollment.id).first()
    assert main._course_no_upload_nos(enr) == set()


def test_course_no_upload_rejects_paid_period(db_session, admin):
    """[F004][S002] Tick is meaningless once the period is confirmed paid."""
    alice, enrollment, _plan = _seed(db_session)
    from app.schemas import CourseInstallmentNoUpload

    with pytest.raises(HTTPException) as exc:
        main.admin_course_set_installment_no_upload(
            enrollment.id,
            CourseInstallmentNoUpload(student_id=alice.id, installment_no=1, no_upload=True),
            db=db_session,
            user=admin,
        )
    assert exc.value.status_code == 400


def test_category_no_document_allows_confirm_without_proof(db_session, monkeypatch, admin):
    """[F004][S002] Category period confirms with the tick even when no receipt was uploaded."""
    alice, _enrollment, plan = _seed(db_session)
    monkeypatch.setattr(main, "send_payment_whatsapp_notifications", lambda *args, **kwargs: {})

    with pytest.raises(HTTPException) as exc:
        main.admin_confirm_category_installment(
            plan_id=plan.id, installment_no=2, payload=None, db=db_session, user=admin
        )
    assert exc.value.status_code == 400

    result = main.admin_set_category_installment_no_document(
        plan_id=plan.id,
        installment_no=2,
        payload=main.CategoryInstallmentNoDocument(no_document_required=True),
        db=db_session,
        user=admin,
    )
    assert result["no_document_required"] is True

    confirmed = main.admin_confirm_category_installment(
        plan_id=plan.id, installment_no=2, payload=None, db=db_session, user=admin
    )
    assert confirmed["ok"] is True
    pay = (
        db_session.query(InstallmentPayment)
        .filter(
            InstallmentPayment.installment_plan_id == plan.id,
            InstallmentPayment.installment_no == 2,
        )
        .first()
    )
    assert pay.paid_at is not None


def test_member_full_payload_exposes_no_document_flags(db_session):
    """[F004][S002] Student page renders ticks from these payload fields."""
    alice, enrollment, plan = _seed(db_session)
    db_session.add_all([
        Attendance(
            student_id=alice.id,
            course_id=enrollment.id,
            coach_id=enrollment.coach_id,
            branch_id=enrollment.branch_id,
            attended_at=datetime(2026, 10, 7, 10),
            session_calendar_date=date(2026, 10, 7),
        ),
        Attendance(
            student_id=alice.id,
            course_id=enrollment.id,
            coach_id=enrollment.coach_id,
            branch_id=enrollment.branch_id,
            attended_at=datetime(2026, 10, 8, 10),
            session_calendar_date=date(2026, 10, 8),
        ),
    ])
    from app.schemas import CourseInstallmentNoUpload

    main.admin_course_set_installment_no_upload(
        enrollment.id,
        CourseInstallmentNoUpload(student_id=alice.id, installment_no=2, no_upload=True),
        db=db_session,
        user=AppUser(username="ops", role="ADMIN", password_salt="", password_hash=""),
    )
    db_session.commit()

    payload = main._member_full_payload(db_session, alice)
    pin_row = next(r for r in payload["course_checkin_pins"] if r["course_id"] == enrollment.id)
    assert pin_row["no_upload_installment_nos"] == [2]
    assert pin_row["lessons_attended"] == 2
    segments = {s["installment_no"]: s for s in pin_row["installment_segments"]}
    assert segments[2]["has_pending_payment"] is False
    assert segments[1]["has_pending_payment"] is False

    pay_row = payload["category_enrollments"][0]["installment_plans"][0]["payments"][1]
    assert pay_row["no_document_required"] is False
