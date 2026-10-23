"""[F005][S003] The agreed four wordings use course-specific money and paired recipients."""

import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import main
from app.course_payment_state import course_payment_state, record_course_payment
from app.models import Attendance, Branch, Coach, CourseEnrollment, Receipt, RenewalRecord, Student
from app.payment_notifications import send_payment_whatsapp_notifications
from app.schemas import CourseCreate, CourseInstallmentMarkPaid, RenewalCreate
from app.enrollment_schedule import parse_segment_pins_json
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
    assert captured[0]["template_key"] == "payment_student_pending"
    assert captured[1]["template_key"] == "payment_coach"
    assert captured[0]["template_context"]["next_lesson_date"] == "待教練安排"
    assert result.payment_whatsapp["student"]["template_key"] == "payment_student_pending"
    new_course = db_session.get(CourseEnrollment, result.id)
    assert course_payment_state(new_course)["paid_total"] == 0
    assert course_payment_state(new_course)["pending_payments"]["1"]["receipt_id"] == receipt.id


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


def test_first_unpaid_pin_has_grace_but_cannot_cross_installment_boundary(db_session, monkeypatch):
    """[F003][S002] Unpaid first term is allowed; lesson 11 requires confirmed term 2 and its own PIN."""
    student, coach, enrollment = _course(db_session)
    monkeypatch.setattr(main, "now_hk", lambda: datetime(2026, 10, 16, 10))
    assert main.resolve_checkin_pin_context(db_session, student, "10192")[0].id == enrollment.id
    for i in range(10):
        day = datetime(2026, 10, 1) + timedelta(days=i)
        db_session.add(Attendance(student_id=student.id, course_id=enrollment.id, coach_id=coach.id,
            branch_id=coach.branch_id, attended_at=day, session_calendar_date=day.date()))
    db_session.commit()
    assert main.resolve_checkin_pin_context(db_session, student, "10192") == "blocked_installment_unpaid"
    record_course_payment(enrollment, amount=3000, installment_no=2, receipt_id=2)
    db_session.commit()
    assert main.resolve_checkin_pin_context(db_session, student, "10192") is None
    assert main.resolve_checkin_pin_context(db_session, student, "10193")[0].id == enrollment.id


def test_new_course_issues_only_first_pin_before_payment(db_session, monkeypatch):
    """[F002][S001] Later PINs are not generated or exposed at checkout."""
    student, coach, _ = _course(db_session)
    monkeypatch.setattr(main, "dispatch_reminder", lambda *args, **kwargs: None)
    result = main._create_course_impl(CourseCreate(title="Grace Pilates", branch_id=coach.branch_id,
        coach_id=coach.id, student_ids=[student.id], total_lessons=30, total_installments=3,
        installment_amounts=[3000]*3, whatsapp_reminder_opt_in=True,
        scheduled_start=datetime(2026,10,19,11), scheduled_end=datetime(2026,10,19,12)),
        db_session, SimpleNamespace(role="ADMIN"))
    segments = result.enrollments[0].installment_segments
    assert len(segments[0].pin) == 5 and segments[0].paid is False
    assert [s.pin for s in segments[1:]] == ["", ""]
    assert not any(s.paid for s in segments)


def test_public_receipt_waits_for_admin_then_issues_new_pin_and_notifies_once(db_session, monkeypatch):
    """[F004][S002] Proof upload cannot confirm payment; Admin confirmation is idempotent."""
    student, _, enrollment = _course(db_session)
    rows = json.loads(enrollment.segment_pins_json)
    for row in rows[1:]:
        row["pin"] = ""
    enrollment.segment_pins_json = json.dumps(rows)
    emitted = []
    monkeypatch.setattr(main, "dispatch_reminder", lambda *args, **kwargs: emitted.append(kwargs))
    monkeypatch.setattr(main, "_save_upload_file", lambda *args: "receipts/sample.png")
    result = main._save_member_receipt_row(db_session, student=student, file=None, member_key="DRILL",
        amount=3000, payment_method="FPS", note="Test", context="Test", source="RENEWAL",
        installment_no=2, course_enrollment_id=enrollment.id, payment_confirmed=False)
    db_session.commit()
    assert result["installment_match"]["pending_admin_confirmation"]
    assert parse_segment_pins_json(enrollment.segment_pins_json)[1].pin == ""
    emitted.clear()
    body = CourseInstallmentMarkPaid(student_id=student.id, installment_no=2)
    confirmed = main.admin_course_mark_installment_paid(enrollment.id, body, db_session, SimpleNamespace(role="ADMIN"))
    pin = confirmed.enrollments[0].installment_segments[1].pin
    assert len(pin) == 5 and pin != enrollment.checkin_pin
    assert [m["template_key"] for m in emitted] == ["payment_student_installment", "payment_coach"]
    assert emitted[0]["template_context"]["pin"] == pin
    main.admin_course_mark_installment_paid(enrollment.id, body, db_session, SimpleNamespace(role="ADMIN"))
    assert len(emitted) == 2
    assert parse_segment_pins_json(enrollment.segment_pins_json)[1].pin == pin


def test_coach_cannot_use_admin_payment_confirmation():
    """[F004][S002] Role authorization is enforced at the HTTP confirmation boundary."""
    main.app.dependency_overrides[main.get_current_user] = lambda: SimpleNamespace(role="COACH", username="drillcoach")
    try:
        response = TestClient(main.app).patch("/api/admin/courses/1/installment-paid", json={"student_id":1,"installment_no":2})
        assert response.status_code == 403
    finally:
        main.app.dependency_overrides.pop(main.get_current_user, None)


@pytest.mark.parametrize("amount,full_payment,expected_key,issued", [
    (1000, False, "payment_student_installment", False),
    (3000, True, "payment_student_full", True),
])
def test_admin_handles_partial_installment_and_final_balance(db_session, monkeypatch, amount, full_payment, expected_key, issued):
    """[F004][S002] Partial funds cannot unlock term 3; full remaining balance issues its fresh PIN."""
    student, _, enrollment = _course(db_session)
    record_course_payment(enrollment, amount=3000, installment_no=1, receipt_id=1)
    record_course_payment(enrollment, amount=3000, installment_no=2, receipt_id=2)
    state = course_payment_state(enrollment)
    state["pending_payments"] = {"full" if full_payment else "3": {"amount": amount, "receipt_id":3,"full_payment":full_payment}}
    enrollment.payment_state_json = json.dumps(state)
    emitted = []
    monkeypatch.setattr(main, "dispatch_reminder", lambda *args, **kwargs: emitted.append(kwargs))
    result = main.admin_course_mark_installment_paid(enrollment.id,
        CourseInstallmentMarkPaid(student_id=student.id, installment_no=3), db_session, SimpleNamespace(role="ADMIN"))
    assert emitted[0]["template_key"] == expected_key
    third = result.enrollments[0].installment_segments[2]
    assert third.paid is issued
    assert bool(third.pin) is issued
    if issued:
        assert third.pin not in {"10192","10193","10194"}
        main.admin_course_mark_installment_paid(enrollment.id,
            CourseInstallmentMarkPaid(student_id=student.id, installment_no=3), db_session, SimpleNamespace(role="ADMIN"))
        assert course_payment_state(enrollment)["paid_total"] == 9000
        assert len(emitted) == 2
    else:
        assert "部分付款待補足" in emitted[0]["template_context"]["payment_status"]


def test_single_payment_course_pending_receipt_can_be_confirmed(db_session, monkeypatch):
    """[F004][S002] SOP3 also works for a course without installment segments."""
    student, _, enrollment = _course(db_session)
    enrollment.segment_pins_json = None
    enrollment.payment_state_json = json.dumps({"total_amount":9000,"pending_payments":{"1":{"amount":9000,"receipt_id":1}}})
    emitted=[]
    monkeypatch.setattr(main, "dispatch_reminder", lambda *args, **kwargs: emitted.append(kwargs))
    result=main.admin_course_mark_installment_paid(enrollment.id,
        CourseInstallmentMarkPaid(student_id=student.id,installment_no=1),db_session,SimpleNamespace(role="ADMIN"))
    assert result.enrollments[0].installment_segments[0].pin == enrollment.checkin_pin
    assert emitted[0]["template_key"] == "payment_student_full"
    assert emitted[1]["template_context"]["amount_owing"] == "HKD 0"


def test_unassigned_receipt_is_linked_to_admin_selected_term_without_double_count(db_session, monkeypatch):
    """[F004][S002] An Admin selects the term for an unscoped uploaded proof, counting it once."""
    student, _, enrollment = _course(db_session)
    enrollment.payment_state_json = json.dumps({"total_amount":9000,"pending_payments":{"unassigned":{"amount":3000,"receipt_id":1}}})
    monkeypatch.setattr(main,"dispatch_reminder",lambda *args,**kwargs:None)
    body=CourseInstallmentMarkPaid(student_id=student.id,installment_no=2)
    main.admin_course_mark_installment_paid(enrollment.id,body,db_session,SimpleNamespace(role="ADMIN"))
    main.admin_course_mark_installment_paid(enrollment.id,body,db_session,SimpleNamespace(role="ADMIN"))
    state=course_payment_state(enrollment)
    assert state["paid_total"] == 3000
    assert state["payments"]["installment:2"]["receipt_id"] == 1
    assert state["pending_payments"] == {}
