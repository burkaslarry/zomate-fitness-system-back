"""[F002][S003] 1-on-2 shared package — primary student A, partner B (read-only view)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from fastapi import HTTPException
from sqlalchemy.orm import Session, joinedload

from .models import CategoryEnrollment, CourseCategory, DuoGroup, Student

DUO_CATEGORY_NAMES = frozenset(
    {
        "新學生一對二",
        "續會學生一對二",
        "自帶學生一對二",
    }
)


def is_duo_course_category(category: CourseCategory | None) -> bool:
    """[F002][S003] Strict whitelist — yoga / pilates / 一對一等課種唔用 duo_group。"""
    if category is None:
        return False
    name = (category.name or "").strip()
    return name in DUO_CATEGORY_NAMES


def duo_group_for_legacy_category(
    db: Session, category_enrollment_id: int | None
) -> DuoGroup | None:
    """[F002][S003] Duo group only when legacy/category ledger is a whitelisted 一對二 kind."""
    if not category_enrollment_id:
        return None
    ce = (
        db.query(CategoryEnrollment)
        .options(joinedload(CategoryEnrollment.course_category))
        .filter(CategoryEnrollment.id == int(category_enrollment_id))
        .first()
    )
    if ce is None or not ce.duo_group_id:
        return None
    if not is_duo_course_category(ce.course_category):
        return None
    return db.get(DuoGroup, int(ce.duo_group_id))


def duo_member_student_ids(group: DuoGroup) -> list[int]:
    return [int(group.primary_student_id), int(group.partner_student_id)]


def shared_course_checkin_count(db: Session, course_id: int, group: DuoGroup) -> int:
    """[F002][S003] Sessions redeemed on shared package — use primary's attendance rows."""
    from .models import Attendance

    return (
        db.query(Attendance)
        .filter(
            Attendance.course_id == course_id,
            Attendance.student_id == int(group.primary_student_id),
        )
        .count()
    )


def duplicate_partner_course_pins(
    db: Session,
    student: Student,
    pins: list[dict[str, Any]],
    *,
    include_deleted: bool,
) -> list[dict[str, Any]]:
    """[F002][S003] Partner B sees primary A's shared PIN cards (一對二 only)."""
    from .models import CourseEnrollment, InstallmentPlan

    existing_ids = {int(p["course_id"]) for p in pins if p.get("course_id")}
    out = list(pins)
    deleted_ids: set[int] = set()
    if not include_deleted:
        from .models import DeletedRecord

        deleted_ids = {
            int(r.entity_id)
            for r in db.query(DeletedRecord)
            .filter(DeletedRecord.entity_type == "course_enrollments")
            .all()
        }

    for group in partner_category_enrollment_mirrors(db, student.id):
        cat_id = group.primary_category_enrollment_id
        if not cat_id:
            continue
        enr = (
            db.query(CourseEnrollment)
            .options(joinedload(CourseEnrollment.branch), joinedload(CourseEnrollment.coach))
            .filter(
                CourseEnrollment.student_id == int(group.primary_student_id),
                CourseEnrollment.legacy_category_enrollment_id == int(cat_id),
            )
            .order_by(CourseEnrollment.id.desc())
            .first()
        )
        if enr is None or enr.id in existing_ids or enr.id in deleted_ids:
            continue
        attended = shared_course_checkin_count(db, enr.id, group)
        meta = duo_meta_for_category_row(
            db, student, group.primary_category_enrollment, group
        )
        row = {
            "course_id": enr.id,
            "course_title": enr.title,
            "branch_id": enr.branch_id,
            "branch_name": enr.branch.name if enr.branch else "—",
            "coach_name": (enr.coach.full_name if enr.coach else None) or "—",
            "coach_id": enr.coach_id,
            "scheduled_start": enr.scheduled_start.isoformat(),
            "series_end_date": enr.series_end_date.isoformat() if enr.series_end_date else None,
            "total_lessons": enr.total_lessons,
            "checkin_pin": enr.checkin_pin,
            "installment_segments": [],
            "no_upload_installment_nos": [],
            "lessons_attended": attended,
            "legacy_prior_lessons": 0,
            "legacy_category_enrollment_id": int(cat_id),
            "legacy_installment_plan_id": None,
            "deleted": False,
            "duo": meta,
            "duo_shared_pin": True,
        }
        plan = (
            db.query(InstallmentPlan)
            .filter(InstallmentPlan.enrollment_id == int(cat_id))
            .order_by(InstallmentPlan.id.asc())
            .first()
        )
        if plan is not None:
            row["legacy_installment_plan_id"] = int(plan.id)
        out.append(row)
        existing_ids.add(enr.id)
    return out


def notify_duo_partner_student_whatsapp(
    db: Session,
    log_whatsapp_fn,
    *,
    group: DuoGroup,
    triggering_student: Student,
    recipient: Student,
    message: str,
    template_key: str | None,
    template_context: dict[str, str] | None,
) -> None:
    """[F002][S003] Send the same student-facing WhatsApp to the other 一對二 member."""
    if int(recipient.id) == int(triggering_student.id):
        return
    if not (recipient.phone or "").strip():
        return
    partner_ctx = dict(template_context or {})
    partner_ctx["student_name"] = (recipient.full_name or "").strip() or partner_ctx.get("student_name", "—")
    log_whatsapp_fn(
        db,
        recipient,
        recipient.phone,
        message.replace(triggering_student.full_name or "", recipient.full_name or ""),
        template_key=template_key,
        template_context=partner_ctx,
    )


def _hk_local_eight(raw: str | None) -> str | None:
    digits = "".join(ch for ch in (raw or "") if ch.isdigit())
    if len(digits) == 11 and digits.startswith("852"):
        tail = digits[3:]
        return tail if len(tail) == 8 else None
    if len(digits) == 8:
        return digits
    return None


def _phone_lookup_variants(local_eight: str) -> list[str]:
    return [local_eight, f"+852{local_eight}", f"852{local_eight}"]


def resolve_partner_student(db: Session, partner_phone: str, *, primary_student_id: int) -> Student:
    """[F002][S003] Look up companion by HK mobile; must differ from primary."""
    local = _hk_local_eight(partner_phone)
    if not local:
        raise HTTPException(status_code=400, detail="同伴電話須為香港 8 位手機號碼。")
    variants = _phone_lookup_variants(local)
    partner = db.query(Student).filter(Student.phone.in_(variants)).first()
    if partner is None:
        raise HTTPException(status_code=404, detail="搵唔到同伴學生，請先登記該電話或檢查號碼。")
    if int(partner.id) == int(primary_student_id):
        raise HTTPException(status_code=400, detail="同伴不能與主學生相同。")
    return partner


def bind_duo_group_to_category_enrollment(
    db: Session,
    *,
    primary_student: Student,
    category_enrollment: CategoryEnrollment,
    partner: Student,
) -> DuoGroup:
    """[F002][S003] Create or update duo group for one primary category ledger."""
    existing = (
        db.query(DuoGroup)
        .filter(DuoGroup.primary_category_enrollment_id == category_enrollment.id)
        .first()
    )
    if existing:
        existing.partner_student_id = partner.id
        existing.primary_student_id = primary_student.id
        existing.course_category_id = category_enrollment.course_category_id
        group = existing
    else:
        group = DuoGroup(
            primary_student_id=primary_student.id,
            partner_student_id=partner.id,
            primary_category_enrollment_id=category_enrollment.id,
            course_category_id=category_enrollment.course_category_id,
        )
        db.add(group)
        db.flush()
    category_enrollment.duo_group_id = group.id
    db.add(category_enrollment)
    return group


def ensure_duo_partner_bound(
    db: Session,
    *,
    primary_student: Student,
    category: CourseCategory,
    enrollment: CategoryEnrollment,
    partner_phone: str | None,
) -> None:
    """[F002][S003] Require B phone when opening 一對二 category ledger on primary A."""
    if not is_duo_course_category(category):
        return
    phone = (partner_phone or "").strip()
    if enrollment.duo_group_id:
        if not phone:
            return
    elif not phone:
        raise HTTPException(status_code=400, detail="一對二 package 必須填寫同伴電話。")
    partner = resolve_partner_student(db, phone, primary_student_id=primary_student.id)
    bind_duo_group_to_category_enrollment(
        db,
        primary_student=primary_student,
        category_enrollment=enrollment,
        partner=partner,
    )


def duo_meta_for_category_row(
    db: Session, student: Student, enrollment: CategoryEnrollment, group: DuoGroup | None
) -> dict[str, Any] | None:
    """[F002][S003] JSON for member detail — primary vs partner."""
    if group is None:
        return None
    primary = db.get(Student, group.primary_student_id)
    partner = db.get(Student, group.partner_student_id)
    is_primary = int(student.id) == int(group.primary_student_id)
    is_partner = int(student.id) == int(group.partner_student_id)
    if not is_primary and not is_partner:
        return None
    return {
        "group_id": group.id,
        "role": "primary" if is_primary else "partner",
        "read_only": not is_primary,
        "primary_student_id": group.primary_student_id,
        "primary_student_name": primary.full_name if primary else "—",
        "primary_student_hkid": (primary.hkid or "").strip() if primary else None,
        "partner_student_id": group.partner_student_id,
        "partner_student_name": partner.full_name if partner else "—",
        "partner_student_hkid": (partner.hkid or "").strip() if partner else None,
        "partner_student_phone": partner.phone if partner else None,
        "anchor_category_enrollment_id": group.primary_category_enrollment_id,
    }


def category_enrollment_payload(
    db: Session,
    student: Student,
    ce: CategoryEnrollment,
    category_prior: dict[int, int],
) -> dict[str, Any]:
    """[F002][S003] One category row for GET member full (incl. duo metadata)."""
    group = ce.duo_group
    if group is None and ce.duo_group_id:
        group = db.get(DuoGroup, ce.duo_group_id)
    duo = duo_meta_for_category_row(db, student, ce, group)
    return {
        "id": ce.id,
        "course_category_id": ce.course_category_id,
        "category_name": ce.course_category.name,
        "status": ce.status,
        "total_lessons": ce.total_lessons,
        "lessons_already_taken": category_prior.get(ce.id, 0),
        "remaining_from_paper": max(0, ce.total_lessons - category_prior.get(ce.id, 0)),
        "started_at": ce.started_at.isoformat(),
        "installment_plans": [
            {
                "id": plan.id,
                "total_installments": plan.total_installments,
                "status": plan.status,
                "created_at": plan.created_at.isoformat(),
                "payments": [
                    {
                        "id": pay.id,
                        "installment_no": pay.installment_no,
                        "amount": float(pay.amount),
                        "due_date": pay.due_date.isoformat(),
                        "paid_at": pay.paid_at.isoformat() if pay.paid_at else None,
                        "status": pay.status,
                        "proof_receipt_id": pay.proof_receipt_id,
                        "proof_uploaded_at": (
                            pay.proof_uploaded_at.isoformat() if pay.proof_uploaded_at else None
                        ),
                        "no_document_required": bool(pay.no_document_required),
                    }
                    for pay in sorted(plan.payments, key=lambda p: p.installment_no)
                ],
            }
            for plan in ce.installment_plans
        ],
        "duo": duo,
    }


def partner_category_enrollment_mirrors(db: Session, student_id: int) -> list[DuoGroup]:
    """[F002][S003] Groups where this student is B (not A)."""
    return (
        db.query(DuoGroup)
        .options(
            joinedload(DuoGroup.primary_category_enrollment).joinedload(CategoryEnrollment.course_category),
            joinedload(DuoGroup.primary_student),
            joinedload(DuoGroup.partner_student),
        )
        .filter(DuoGroup.partner_student_id == student_id)
        .all()
    )


def member_category_enrollments(
    db: Session,
    student: Student,
    category_prior: dict[int, int],
    *,
    primary_prior_fn: Callable[[int], dict[int, int]] | None = None,
) -> list[dict[str, Any]]:
    """[F002][S003] Own rows plus partner read-only mirrors of primary's package."""
    from .models import InstallmentPlan

    def _prior_for_primary(primary_student_id: int) -> dict[int, int]:
        if primary_prior_fn is not None:
            return primary_prior_fn(primary_student_id)
        return {}

    own = (
        db.query(CategoryEnrollment)
        .options(
            joinedload(CategoryEnrollment.course_category),
            joinedload(CategoryEnrollment.duo_group),
            joinedload(CategoryEnrollment.installment_plans).joinedload(InstallmentPlan.payments),
        )
        .filter(CategoryEnrollment.student_id == student.id)
        .all()
    )
    rows = [category_enrollment_payload(db, student, ce, category_prior) for ce in own]
    for group in partner_category_enrollment_mirrors(db, student.id):
        ce = group.primary_category_enrollment
        if ce is None:
            continue
        prior = (
            category_prior
            if int(group.primary_student_id) == int(student.id)
            else _prior_for_primary(int(group.primary_student_id))
        )
        payload = category_enrollment_payload(db, student, ce, prior)
        payload["duo_mirrored"] = True
        payload["duo"] = duo_meta_for_category_row(db, student, ce, group)
        rows.append(payload)
    return rows