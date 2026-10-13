"""[F005][S003] The agreed four wordings use course-specific money and paired recipients."""

import json
from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import main
from app.course_payment_state import course_payment_state, record_course_payment
from app.models import Branch, Coach, CourseEnrollment, Receipt, RenewalRecord, Student
from app.payment_notifications import send_payment_whatsapp_notifications
from app.schemas import CourseCreate, RenewalCreate
from app.whatsapp_templates import DEFAULT_WHATSAPP_TEMPLATES, get_template_body


def _course(db):
    """[F005][S003] Set up three FPS installments with their own scoped financial facts."""
    branch = Branch(name="Drill", code="DRILL", address="Test", active=True)
    coach = Coach(full_name="Fung Lo", phone="91234567", branch=branch, active=True)
    student = Student(full_name="Larry Lo", phone="93103031", whatsapp_reminder_opt_in=True)
    db.add_all([branch, coach, student])
    db.flush()
    enrollment = CourseEnrollment(
        title="Pilates", branch_id=branch.id, coach_id=coach.id, student_id=student.id,
        scheduled_start=datetime(2026, 10, 16, 10), scheduled_end=datetime(2026, 10, 16, 11),
        checkin_pin="10192", total_lessons=30, coach_time_confirmed=True,
        segment_pins_json=json.dumps([
            {"installment_no": i, "lesson_from": 1+(i-1)*10, "lesson_to": i*10,
             "pin": str(10191+i), "paid": False, "amount_hkd": 3000}
            for i in range(1, 4)
        ]),
    )
    db.add(enrollment)
    db.commit()
    return student, coach, enrollment


def _messages(db, student, enrollment):
    """[F005][S003] Capture paired reminders without transmitting anything."""
    emitted = []

    def capture(db, student, phone, message, **kwargs):
        """[F005][S003] Record context and the exact client-approved rendered body."""
        emitted.append({"phone": phone, "message": message, **kwargs})

    result = send_payment_whatsapp_notifications(
        db, capture, student=student, course_enrollment_id=enrollment.id, receipt_confirmed=None,
    )
    return emitted, result


def test_three_installments_then_full_balance_use_only_the_four_agreed_templates(db_session):
    """[F005][S003] First/second installments and final payment update both sides accurately."""
    student, coach, enrollment = _course(db_session)
    emitted, _ = _messages(db_session, student, enrollment)
    assert [m["template_key"] for m in emitted] == ["payment_student_pending", "payment_coach"]
    for installment, expected_key, owing in [(1, "payment_student_installment", 6000),
                                             (2, "payment_student_installment", 3000),
                                             (3, "payment_student_full", 0)]:
        record_course_payment(enrollment, amount=3000, installment_no=installment, receipt_id=installment)
        emitted, _ = _messages(db_session, student, enrollment)
        assert [m["template_key"] for m in emitted] == [expected_key, "payment_coach"]
        assert [m["phone"] for m in emitted] == [student.phone, coach.phone]
        context = emitted[0]["template_context"]
        assert context["total_amount"] == "HKD 9000"
        assert context["amount_paid"] == "HKD 3000"
        assert context["amount_owing"] == f"HKD {owing}"
        assert "如有疑問，請 WhatsApp 6052 9291 查詢。此號碼用作系統通知。" in emitted[0]["message"]
        if installment == 1:
            assert context["installment_notes"] == "第9堂付第2期；第19堂付第3期"
    assert course_payment_state(enrollment)["paid_total"] == 9000
    assert _messages(db_session, student, enrollment)[1]["student"]["wa_me_url"].startswith("https://wa.me/85293103031?")


def test_receipt_replacement_does_not_double_count_and_other_courses_do_not_pollute_money(db_session):
    """[F005][S003] Payment totals stay tied to the current course and installment."""
    student, _, enrollment = _course(db_session)
    db_session.add(Receipt(student_id=student.id, member_hkid="T123", file_path="other.png", amount=99000, source="RENEWAL"))
    record_course_payment(enrollment, amount=3000, installment_no=1, receipt_id=1)
    record_course_payment(enrollment, amount=3000, installment_no=1, receipt_id=2)
    db_session.commit()
    emitted, _ = _messages(db_session, student, enrollment)
    assert course_payment_state(enrollment)["paid_total"] == 3000
    assert emitted[0]["template_context"]["amount_owing"] == "HKD 6000"
    with pytest.raises(HTTPException):
        record_course_payment(enrollment, amount=1000, full_payment=True, receipt_id=3)
    assert course_payment_state(enrollment)["paid_total"] == 3000


def test_payment_without_receipt_cannot_claim_receipt_uploaded(db_session):
    """[F005][S003] Preserve the truth of the client's fixed receipt heading."""
    student, _, enrollment = _course(db_session)
    record_course_payment(enrollment, amount=3000, installment_no=1)
    emitted, _ = _messages(db_session, student, enrollment)
    assert emitted[0]["template_key"] == "payment_student_pending"


def test_linked_checkout_notifies_after_course_pin_and_payment_are_saved(db_session, monkeypatch):
    """[F002][S001] The new enrollment supplies the correct PIN and first-installment context."""
    student, coach, old_course = _course(db_session)
    receipt = Receipt(student_id=student.id, member_hkid="T123", file_path="fps.png", amount=3000, source="RENEWAL")
    db_session.add(receipt)
    db_session.flush()
    renewal = RenewalRecord(student_id=student.id, student_name=student.full_name, phone=student.phone,
        course_ratio="1:1", lessons=30, payment_method="FPS", coach_id=coach.id,
        amount=3000, receipt_id=receipt.id, applicant_name=student.full_name,
        signature="Test", renewal_date=datetime(2026, 10, 13).date())
    db_session.add(renewal)
    db_session.commit()
    captured = []

    def capture(phone, message, **kwargs):
        """[F005][S003] Check committed course/payment ownership at the provider boundary."""
        enrollment = db_session.query(CourseEnrollment).filter(CourseEnrollment.title == "New Pilates").one()
        assert course_payment_state(enrollment)["renewal_id"] == renewal.id
        assert kwargs["template_context"]["pin"] == enrollment.checkin_pin
        captured.append(kwargs)

    monkeypatch.setattr(main, "dispatch_reminder", capture)
    body = CourseCreate(title="New Pilates", branch_id=coach.branch_id, coach_id=coach.id,
        scheduled_start=datetime(2026, 10, 13, 10), scheduled_end=datetime(2026, 10, 13, 11),
        student_ids=[student.id], total_lessons=30, total_installments=3, installment_amounts=[3000]*3,
        whatsapp_reminder_opt_in=True, payment_renewal_id=renewal.id, payment_total_amount=9000,
        payment_received=True)
    result = main._create_course_impl(body, db_session, SimpleNamespace(role="ADMIN"))
    assert result.id != old_course.id
    assert len(captured) == 2
    assert captured[0]["template_key"] == "payment_student_installment"
    assert captured[1]["template_key"] == "payment_coach"
    assert captured[0]["template_context"]["next_lesson_date"] == "待教練安排"
    assert result.payment_whatsapp["student"]["template_key"] == "payment_student_installment"


def test_course_registration_requires_explicit_consent():
    """[F001][S001] API clients cannot bypass the unchecked submit-button gate."""
    with pytest.raises(ValidationError, match="WhatsApp"):
        CourseCreate(title="Test", branch_id=1, coach_id=1, student_ids=[1],
            scheduled_start=datetime(2026, 10, 13, 10), scheduled_end=datetime(2026, 10, 13, 11))


def test_registration_consent_failure_is_422_not_serialization_error():
    """[F001][S001] Unchecked consent must produce a usable API error, without reflecting private input."""
    response = TestClient(main.app).post("/api/v1/students/register", json={
        "full_name": "Drill", "hkid": "DRILL001", "phone": "93103031", "date_of_birth": "1990-01-01",
        "emergency_contact_name": "Drill", "emergency_contact_phone": "93103031", "form_type": "new",
        "parq": {}, "digital_signature": "x" * 20, "package_sessions": 30,
        "whatsapp_reminder_opt_in": False,
    })
    assert response.status_code == 422
    assert "WhatsApp" in response.json()["details"][0]["msg"]
    assert "93103031" not in response.text


def test_fixed_bodies_match_meta_approved_wording(db_session):
    """[F005][S003] A database preview cannot alter the four agreed message texts."""
    for row in DEFAULT_WHATSAPP_TEMPLATES:
        if row["key"].startswith("payment_"):
            assert get_template_body(db_session, row["key"]) == row["body"]
            assert "課程開始日期：{{next_lesson_date}}" in row["body"]
            assert "測試課程" not in row["body"]
