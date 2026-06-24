"""[F005][S003]
Feature: Balance Sync & Integrations
Step: Payment receipt matching + WhatsApp reminders
Logic: Mark installments paid on receipt upload; render templates; log student/coach WhatsApp messages.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session, joinedload

from .enrollment_schedule import parse_segment_pins_json
from .models import (
    CategoryEnrollment,
    Coach,
    CourseEnrollment,
    InstallmentPayment,
    InstallmentPlan,
    Receipt,
    RenewalRecord,
    Student,
)
from .whatsapp_templates import (
    build_installment_notes_from_segments,
    build_payment_context,
    count_course_checkins,
    derive_payment_amounts,
    format_lesson_datetime,
    get_template_body,
    render_whatsapp_template,
    resolve_payment_template_key,
    sum_receipt_amounts,
)

if TYPE_CHECKING:
    pass


def wa_me_link(phone: str, message: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    return f"https://wa.me/{digits}?text={quote(message)}"


def _mark_course_installment_paid(enr: CourseEnrollment, installment_no: int) -> None:
    raw = getattr(enr, "segment_pins_json", None)
    if not raw:
        raise HTTPException(status_code=400, detail="This enrollment has no installment PIN segments.")
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Corrupt installment segment payload.") from exc
    if not isinstance(rows, list):
        raise HTTPException(status_code=500, detail="Invalid installment segment payload.")
    touched = False
    for row in rows:
        if isinstance(row, dict) and int(row.get("installment_no") or 0) == installment_no:
            row["paid"] = True
            touched = True
            break
    if not touched:
        raise HTTPException(status_code=404, detail="Installment segment not found for this enrollment.")
    enr.segment_pins_json = json.dumps(rows, ensure_ascii=False)


def _mark_course_full_paid(enr: CourseEnrollment) -> bool:
    raw = getattr(enr, "segment_pins_json", None)
    if not raw:
        return False
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Corrupt installment segment payload.") from exc
    if not isinstance(rows, list):
        raise HTTPException(status_code=500, detail="Invalid installment segment payload.")
    touched = False
    for row in rows:
        if isinstance(row, dict):
            row["paid"] = True
            touched = True
    if touched:
        enr.segment_pins_json = json.dumps(rows, ensure_ascii=False)
    return touched


def _mark_category_installment_paid(
    db: Session,
    plan_id: int,
    installment_no: int,
    amount: float | None,
) -> InstallmentPayment:
    pay = (
        db.query(InstallmentPayment)
        .filter(
            InstallmentPayment.installment_plan_id == plan_id,
            InstallmentPayment.installment_no == installment_no,
        )
        .first()
    )
    if pay is None:
        raise HTTPException(status_code=404, detail="Installment payment row not found.")
    if amount is not None and amount > 0:
        pay.amount = amount
    pay.status = "paid"
    pay.paid_at = datetime.utcnow()
    return pay


def apply_receipt_payment_match(
    db: Session,
    *,
    student: Student,
    installment_no: int | None,
    course_enrollment_id: int | None,
    installment_plan_id: int | None,
    amount: float | None,
    full_payment: bool = False,
) -> dict[str, Any]:
    """[F004][S002] Link uploaded receipt to installment (course segment or category plan)."""
    out: dict[str, Any] = {"installment_marked_paid": False, "full_payment_marked_paid": False}
    if installment_no is None and not full_payment:
        return out
    if course_enrollment_id is not None:
        enr = (
            db.query(CourseEnrollment)
            .filter(
                CourseEnrollment.id == course_enrollment_id,
                CourseEnrollment.student_id == student.id,
            )
            .first()
        )
        if not enr:
            raise HTTPException(status_code=404, detail="Course enrollment not found for this student.")
        if full_payment:
            out["full_payment_marked_paid"] = _mark_course_full_paid(enr)
            out["course_enrollment_id"] = course_enrollment_id
            return out
        if installment_no is None:
            return out
        _mark_course_installment_paid(enr, installment_no)
        out["installment_marked_paid"] = True
        out["course_enrollment_id"] = course_enrollment_id
        return out
    if installment_plan_id is not None:
        plan = (
            db.query(InstallmentPlan)
            .options(joinedload(InstallmentPlan.payments))
            .filter(InstallmentPlan.id == installment_plan_id)
            .first()
        )
        if plan is None:
            raise HTTPException(status_code=404, detail="Installment plan not found.")
        cat = db.get(CategoryEnrollment, plan.enrollment_id)
        if cat is None or cat.student_id != student.id:
            raise HTTPException(status_code=404, detail="Category enrollment not found for this student.")
        _mark_category_installment_paid(db, installment_plan_id, installment_no, amount)
        out["installment_marked_paid"] = True
        out["installment_plan_id"] = installment_plan_id
        return out
    return out


def _resolve_course_enrollment(
    db: Session,
    student_id: int,
    course_enrollment_id: int | None,
) -> CourseEnrollment | None:
    if course_enrollment_id is None:
        return (
            db.query(CourseEnrollment)
            .filter(CourseEnrollment.student_id == student_id)
            .order_by(CourseEnrollment.created_at.desc())
            .first()
        )
    return (
        db.query(CourseEnrollment)
        .filter(CourseEnrollment.id == course_enrollment_id, CourseEnrollment.student_id == student_id)
        .first()
    )


def _payment_status_label(is_installment: bool, receipt_confirmed: bool, segments: list) -> str:
    if not receipt_confirmed:
        return "待確認"
    if not is_installment:
        return "已付款"
    paid_n = sum(1 for s in segments if getattr(s, "paid", False) or (isinstance(s, dict) and s.get("paid")))
    total_n = len(segments) if segments else 0
    if total_n <= 1:
        return "已付款"
    if paid_n >= total_n:
        return "已付清"
    return "已分期"


def send_payment_whatsapp_notifications(
    db: Session,
    log_whatsapp_fn,
    *,
    student: Student,
    receipt_confirmed: bool = True,
    notify_coach: bool = True,
    course_enrollment_id: int | None = None,
    installment_no: int | None = None,
    installment_plan_id: int | None = None,
    amount: float | None = None,
    full_payment: bool = False,
) -> dict[str, Any]:
    """[F005][S003] Render templates and log WhatsApp messages for student (+ optional coach)."""
    enr = _resolve_course_enrollment(db, student.id, course_enrollment_id)
    coach: Coach | None = None
    if enr is not None and enr.coach_id:
        coach = db.get(Coach, enr.coach_id)

    segments = parse_segment_pins_json(enr.segment_pins_json) if enr and enr.segment_pins_json else []
    segment_dicts: list[dict] = []
    if enr and enr.segment_pins_json:
        try:
            raw = json.loads(enr.segment_pins_json)
            if isinstance(raw, list):
                segment_dicts = [r for r in raw if isinstance(r, dict)]
        except json.JSONDecodeError:
            segment_dicts = []

    is_installment = (len(segments) > 1 or installment_plan_id is not None or installment_no is not None) and not full_payment
    if installment_plan_id is not None:
        plan = db.get(InstallmentPlan, installment_plan_id)
        if plan and plan.total_installments > 1:
            is_installment = True

    course_title = enr.title if enr else "—"
    if course_title == "—" and installment_plan_id is not None:
        plan = db.get(InstallmentPlan, installment_plan_id)
        if plan:
            cat = (
                db.query(CategoryEnrollment)
                .options(joinedload(CategoryEnrollment.course_category))
                .filter(CategoryEnrollment.id == plan.enrollment_id)
                .first()
            )
            if cat and cat.course_category:
                course_title = cat.course_category.name

    pin = enr.checkin_pin if enr else "—"
    attended = count_course_checkins(db, student.id, enr.id if enr else None)
    total_lessons = int(enr.total_lessons) if enr and enr.total_lessons else 0
    remaining = max(0, total_lessons - attended) if total_lessons else 0

    receipts = db.query(Receipt).filter(Receipt.student_id == student.id).all()
    renewal = (
        db.query(RenewalRecord)
        .filter(RenewalRecord.student_id == student.id)
        .order_by(RenewalRecord.created_at.desc())
        .first()
    )
    inst_payments: list[InstallmentPayment] = []
    if installment_plan_id is not None:
        inst_payments = (
            db.query(InstallmentPayment)
            .filter(InstallmentPayment.installment_plan_id == installment_plan_id)
            .all()
        )

    paid_amt, total_amt, owing = derive_payment_amounts(
        receipt_amount=amount,
        total_receipts=sum_receipt_amounts(receipts),
        installment_payments=inst_payments or None,
        renewal_amount=float(renewal.amount) if renewal and renewal.amount is not None else None,
        is_installment=is_installment,
    )
    payment_status = _payment_status_label(is_installment, receipt_confirmed, segments)
    installment_notes = build_installment_notes_from_segments(segment_dicts) if segment_dicts else ""

    ctx = build_payment_context(
        student=student,
        course_title=course_title,
        pin=pin,
        next_lesson_date=format_lesson_datetime(enr),
        lessons_attended=attended,
        lessons_remaining=remaining,
        payment_status=payment_status,
        amount_paid=paid_amt,
        total_amount=total_amt,
        amount_owing=owing,
        installment_notes=installment_notes,
    )

    student_key = resolve_payment_template_key(
        receipt_confirmed=receipt_confirmed,
        is_installment=is_installment,
        audience="student",
    )
    student_msg = render_whatsapp_template(get_template_body(db, student_key), ctx)
    log_whatsapp_fn(
        db,
        student,
        student.phone,
        student_msg,
        template_key=student_key,
        template_context=ctx,
    )

    result: dict[str, Any] = {
        "student": {
            "recipient": student.phone,
            "message": student_msg,
            "wa_me_url": wa_me_link(student.phone, student_msg),
            "template_key": student_key,
        },
        "coach": None,
    }

    if notify_coach and coach and coach.phone:
        coach_key = resolve_payment_template_key(
            receipt_confirmed=receipt_confirmed,
            is_installment=is_installment,
            audience="coach",
        )
        coach_msg = render_whatsapp_template(get_template_body(db, coach_key), ctx)
        log_whatsapp_fn(
            db,
            student,
            coach.phone,
            coach_msg,
            template_key=coach_key,
            template_context=ctx,
        )
        result["coach"] = {
            "recipient": coach.phone,
            "message": coach_msg,
            "wa_me_url": wa_me_link(coach.phone, coach_msg),
            "template_key": coach_key,
        }

    return result
