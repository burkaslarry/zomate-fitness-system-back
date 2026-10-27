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
from .course_payment_state import course_payment_state
from .whatsapp_business import normalize_whatsapp_phone
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
    """[F005][S003] Manual fallback links use the same default +852 as API delivery."""
    digits = normalize_whatsapp_phone(phone)
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
            if installment_no > 1 and not row.get("paid"):
                row["pin"] = ""  # [F003][S002] Replace legacy pre-issued codes at actual approval.
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
            if int(row.get("installment_no") or 0) > 1 and not row.get("paid"):
                row["pin"] = ""
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


def _resolve_notification_pin(
    enr: CourseEnrollment | None,
    segment_dicts: list[dict],
    installment_no: int | None,
    full_payment: bool,
) -> str:
    """[F005][S003] Pick segment PIN after installment receipt — unlock tranche for student message."""
    if not enr:
        return "—"
    if segment_dicts:
        if installment_no is not None:
            for seg in segment_dicts:
                if int(seg.get("installment_no") or 0) == installment_no:
                    if installment_no > 1 and not seg.get("paid"):
                        return "待 Admin 確認付款後發出"
                    return str(seg.get("pin") or enr.checkin_pin or "—")
        if full_payment:
            for seg in segment_dicts:
                pin = str(seg.get("pin") or "").strip()
                if pin:
                    return pin
        paid_segs = [s for s in segment_dicts if s.get("paid")]
        if paid_segs:
            latest = max(paid_segs, key=lambda s: int(s.get("installment_no") or 0))
            return str(latest.get("pin") or enr.checkin_pin or "—")
    return str(enr.checkin_pin or "—")


def _format_next_lesson_date(enr: CourseEnrollment | None) -> str:
    """[F005][S003] Match reminder_student.txt — date-only next lesson."""
    if enr is None or enr.scheduled_start is None:
        return "—"
    if not enr.coach_time_confirmed:
        return "待教練安排"
    return enr.scheduled_start.strftime("%Y-%m-%d")


def _payment_status_label(is_installment: bool, receipt_confirmed: bool, segments: list) -> str:
    """[F005][S003] WhatsApp ``payment_status`` — Admin confirm → 付款已確認."""
    if not receipt_confirmed:
        return "待確認"
    if not is_installment:
        return "付款已確認"
    paid_n = sum(1 for s in segments if getattr(s, "paid", False) or (isinstance(s, dict) and s.get("paid")))
    total_n = len(segments) if segments else 0
    if total_n <= 1:
        return "付款已確認"
    if paid_n >= total_n:
        return "付款已確認"
    return "已分期"


def send_payment_whatsapp_notifications(
    db: Session,
    log_whatsapp_fn,
    *,
    student: Student,
    receipt_confirmed: bool | None = None,
    notify_coach: bool = True,
    course_enrollment_id: int | None = None,
    installment_no: int | None = None,
    installment_plan_id: int | None = None,
    amount: float | None = None,
    full_payment: bool = False,
    log_messages: bool = True,
) -> dict[str, Any]:
    """[F005][S003] Render templates and log WhatsApp messages for student (+ optional coach)."""
    enr = _resolve_course_enrollment(db, student.id, course_enrollment_id)
    # [F005][S003] Automatic notifications read the selected course's recorded payment status.
    payment_state = course_payment_state(enr)
    if receipt_confirmed is None:
        receipt_confirmed = bool(payment_state.get("confirmed") and payment_state.get("receipt_uploaded"))
    full_payment = full_payment or bool(payment_state.get("fully_paid"))
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
    if installment_plan_id is not None and not full_payment:
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

    pin = _resolve_notification_pin(enr, segment_dicts, installment_no, full_payment)
    attended = count_course_checkins(db, student.id, enr.id if enr else None)
    total_lessons = int(enr.total_lessons) if enr and enr.total_lessons else 0
    remaining = max(0, total_lessons - attended) if total_lessons else 0
    # [F005][S003] After check-in, show the PIN for the next redeemable lesson tranche.
    if installment_no is None and segment_dicts:
        next_segment = next((s for s in segment_dicts if int(s.get("lesson_from", 0)) <= attended + 1 <= int(s.get("lesson_to", 0))), None)
        if next_segment:
            pin = str(next_segment.get("pin") or pin) if int(next_segment.get("installment_no", 1)) == 1 or next_segment.get("paid") else "待 Admin 確認付款後發出"

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
    if enr is not None:
        # [F005][S003] Never put another enrollment's money into this course's notification.
        paid_amt = amount if amount is not None else payment_state.get("last_amount")
        total_amt = payment_state.get("total_amount")
        if total_amt is None and segment_dicts and all(s.get("amount_hkd") is not None for s in segment_dicts):
            total_amt = sum(float(s["amount_hkd"]) for s in segment_dicts)
        # Confirmed payments + pending checkout amounts (e.g. 第1期 recorded but not Admin-confirmed).
        paid_total = float(payment_state.get("paid_total") or 0)
        pending = payment_state.get("pending_payments") or {}
        pending_sum = 0.0
        if isinstance(pending, dict):
            for row in pending.values():
                if isinstance(row, dict) and row.get("amount") is not None:
                    try:
                        pending_sum += float(row["amount"])
                    except (TypeError, ValueError):
                        pass
        seg_paid = sum(
            float(s.get("amount_hkd") or 0)
            for s in segment_dicts
            if s.get("paid") and s.get("amount_hkd") is not None
        )
        effective_paid = max(paid_total, pending_sum, seg_paid)
        if amount is not None:
            effective_paid = max(effective_paid, float(amount))
        if paid_amt is None and effective_paid > 0:
            paid_amt = effective_paid
        owing = max(0.0, float(total_amt) - effective_paid) if total_amt is not None else None
    payment_status = _payment_status_label(is_installment, receipt_confirmed, segments)
    if receipt_confirmed and is_installment and payment_state.get("last_installment_no"):
        last_no = payment_state["last_installment_no"]
        last_segment = next((s for s in segment_dicts if int(s.get("installment_no", 0)) == last_no), {})
        # [F005][S003] Confirmed tranche → 付款已確認; underpaid stay partial.
        payment_status = (
            f"付款已確認（第{last_no}期）"
            if last_segment.get("paid")
            else "已分期（部分付款待補足）"
        )
    installment_notes = build_installment_notes_from_segments(segment_dicts) if segment_dicts else ""
    branch_code = None
    if enr is not None and enr.branch_id:
        from .models import Branch

        br = db.get(Branch, enr.branch_id)
        branch_code = br.code if br else None

    ctx = build_payment_context(
        student=student,
        course_title=course_title,
        pin=pin,
        next_lesson_date=_format_next_lesson_date(enr),
        lessons_attended=attended,
        lessons_remaining=remaining,
        payment_status=payment_status,
        amount_paid=paid_amt,
        total_amount=total_amt,
        amount_owing=owing,
        installment_notes=installment_notes,
        student_display_name=format_student_display_name(student, branch_code),
    )

    student_key = resolve_payment_template_key(
        receipt_confirmed=receipt_confirmed,
        is_installment=is_installment,
        audience="student",
    )
    student_msg = render_whatsapp_template(get_template_body(db, student_key), ctx)
    if log_messages:
        log_whatsapp_fn(
            db,
            student,
            student.phone,
            student_msg,
            template_key=student_key,
            template_context=ctx,
        )

    result: dict[str, Any] = {
        "is_installment": is_installment,
        "pin_unlocked": pin,
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
        if log_messages:
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


def branch_code_prefix(branch_code: str | None) -> str:
    """[F005][S003] Display prefix e.g. (sw) / (tst) from branch code."""
    code = (branch_code or "").strip().lower()
    if not code:
        return ""
    if code in {"sheungwan", "sw"}:
        return "(sw)"
    if code in {"tst", "tsimshatsui", "tsim_sha_tsui"}:
        return "(tst)"
    return f"({code})"


def format_student_display_name(student: Student, branch_code: str | None = None) -> str:
    """[F005][S003] Prefixed name for UI / WhatsApp: ``(sw)Alex``.

    Prefers explicit ``branch_code``, else student's home branch from registration.
    """
    name = (student.full_name or "").strip() or "—"
    code = (branch_code or "").strip() or None
    if not code:
        home = getattr(student, "branch", None)
        if home is not None and getattr(home, "code", None):
            code = str(home.code)
    prefix = branch_code_prefix(code)
    return f"{prefix}{name}" if prefix else name


def send_schedule_booking_whatsapp(
    db: Session,
    log_whatsapp_fn,
    *,
    student: Student,
    enrollment: CourseEnrollment,
    coach: Coach | None = None,
    notify_coach: bool = True,
) -> dict[str, Any]:
    """[F005][S003]
    Feature: Balance Sync & Integrations
    Step: WhatsApp after coach books / confirms schedule (not payment templates)
    Logic: Match reminder_student.txt 教練booking wording.
    """
    if coach is None and enrollment.coach_id:
        coach = db.get(Coach, enrollment.coach_id)
    branch_code = None
    if enrollment.branch_id:
        from .models import Branch

        br = db.get(Branch, enrollment.branch_id)
        branch_code = br.code if br else None
    student_label = format_student_display_name(student, branch_code)
    phone_display = "".join(ch for ch in (student.phone or "") if ch.isdigit())
    if len(phone_display) == 11 and phone_display.startswith("852"):
        phone_display = phone_display[3:]
    attended = count_course_checkins(db, student.id, enrollment.id)
    total_lessons = int(enrollment.total_lessons or 0)
    remaining = max(0, total_lessons - attended) if total_lessons else 0
    payment_state = course_payment_state(enrollment)
    payment_status = "已付款" if payment_state.get("confirmed") or payment_state.get("fully_paid") else "未付款"
    lesson_when = format_lesson_datetime(enrollment) if enrollment.coach_time_confirmed else "待教練安排"
    if enrollment.scheduled_start and enrollment.coach_time_confirmed:
        lesson_when = enrollment.scheduled_start.strftime("%Y-%m-%d %H:%M")
    coach_name = (coach.full_name if coach else "") or "—"
    pin = str(enrollment.checkin_pin or "—")
    msg = (
        f"【Zomate 開課】{enrollment.title}\n"
        f"{student_label}（{phone_display or student.phone}）\n"
        f"課堂 PIN：{pin}\n"
        f"上堂時間 : {lesson_when}\n"
        f"教練 : {coach_name}\n"
        f"已上堂數: {attended}\n"
        f"餘下堂數: {remaining}\n"
        f"付款狀態: {payment_status}\n"
        "如需要改期，請於24小時前通知教練"
    )
    result: dict[str, Any] = {"student": None, "coach": None}
    log_whatsapp_fn(
        db,
        student,
        student.phone,
        msg,
        template_key="schedule_booking_student",
        template_context={
            "student_name": student_label,
            "course_title": enrollment.title,
            "pin": pin,
            "next_lesson_date": lesson_when,
            "coach_name": coach_name,
            "lessons_attended": str(attended),
            "lessons_remaining": str(remaining),
            "payment_status": payment_status,
            "branch_code": branch_code or "",
        },
    )
    result["student"] = {
        "recipient": student.phone,
        "message": msg,
        "wa_me_url": wa_me_link(student.phone, msg),
        "template_key": "schedule_booking_student",
    }
    if notify_coach and coach and (coach.phone or "").strip():
        # [F005][S003] Match docs/reminder_coach.txt「教練booking」(no PIN).
        coach_msg = (
            f"【Zomate 開課】{enrollment.title}\n"
            f"{student_label}（{phone_display or student.phone}）\n"
            f"上堂時間 : {lesson_when}\n"
            f"教練 : {coach_name}\n"
            f"已上堂數: {attended}\n"
            f"餘下堂數: {remaining}\n"
            f"付款狀態: {payment_status}\n"
            "如需要改期，請於24小時前通知教練"
        )
        log_whatsapp_fn(
            db,
            student,
            coach.phone,
            coach_msg,
            template_key="schedule_booking_coach",
            template_context={
                "student_name": student_label,
                "course_title": enrollment.title,
                "next_lesson_date": lesson_when,
                "coach_name": coach_name,
                "lessons_attended": str(attended),
                "lessons_remaining": str(remaining),
                "payment_status": payment_status,
            },
        )
        result["coach"] = {
            "recipient": coach.phone,
            "message": coach_msg,
            "wa_me_url": wa_me_link(coach.phone, coach_msg),
            "template_key": "schedule_booking_coach",
        }
    return result


def send_checkin_coach_whatsapp(
    db: Session,
    log_whatsapp_fn,
    *,
    student: Student,
    enrollment: CourseEnrollment,
    coach: Coach | None,
    lesson_balance_after: int,
    checked_in_at: datetime | None = None,
) -> dict[str, Any] | None:
    """[F003][S003]
    Feature: Attendance & Today-Only QR Check-in
    Step: WhatsApp notify assigned coach after successful student check-in
    Logic: One dedicated coach message (not payment templates).
    """
    if coach is None or not (coach.phone or "").strip():
        return None
    attended = count_course_checkins(db, student.id, enrollment.id)
    total_lessons = int(enrollment.total_lessons or 0)
    remaining = max(0, int(lesson_balance_after))
    when = (checked_in_at or datetime.utcnow()).strftime("%Y-%m-%d %H:%M")
    phone_display = "".join(ch for ch in (student.phone or "") if ch.isdigit())
    if len(phone_display) == 11 and phone_display.startswith("852"):
        phone_display = phone_display[3:]
    msg = (
        f"【Zomate 簽到通知】{enrollment.title}\n"
        f"學生：{student.full_name}（{phone_display or student.phone}）\n"
        f"已成功簽到並扣 1 堂\n"
        f"簽到時間：{when}\n"
        f"本課程已上：{attended} 堂\n"
        f"學生餘下堂數：{remaining}\n\n"
        "如有疑問，請 WhatsApp 6052 9291 查詢。此號碼用作系統通知。"
    )
    log_whatsapp_fn(
        db,
        student,
        coach.phone,
        msg,
        template_key="checkin_coach",
        template_context={
            "student_name": student.full_name,
            "course_title": enrollment.title,
            "lessons_attended": str(attended),
            "lessons_remaining": str(remaining),
            "checked_in_at": when,
        },
    )
    return {
        "recipient": coach.phone,
        "message": msg,
        "wa_me_url": wa_me_link(coach.phone, msg),
        "template_key": "checkin_coach",
    }


def send_receipt_upload_request_whatsapp(
    db: Session,
    log_whatsapp_fn,
    *,
    student: Student,
    course_enrollment_id: int | None = None,
) -> dict[str, Any]:
    """[F005][S003] Log + return wa.me link asking student to upload payment receipt."""
    enr = _resolve_course_enrollment(db, student.id, course_enrollment_id)
    course_title = enr.title if enr else "—"
    attended = count_course_checkins(db, student.id, enr.id if enr else None)
    total_lessons = int(enr.total_lessons) if enr and enr.total_lessons else 0
    remaining = max(0, total_lessons - attended) if total_lessons else 0
    ctx = build_payment_context(
        student=student,
        course_title=course_title,
        pin=enr.checkin_pin if enr else "—",
        next_lesson_date=format_lesson_datetime(enr),
        lessons_attended=attended,
        lessons_remaining=remaining,
        payment_status="待上傳收據",
        amount_paid=None,
        total_amount=None,
        amount_owing=None,
        installment_notes="",
    )
    template_key = "receipt_upload_request"
    msg = render_whatsapp_template(get_template_body(db, template_key), ctx)
    log_whatsapp_fn(
        db,
        student,
        student.phone,
        msg,
        template_key=template_key,
        template_context=ctx,
    )
    return {
        "message": msg,
        "wa_me_url": wa_me_link(student.phone, msg),
        "template_key": template_key,
    }
