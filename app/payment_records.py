"""[F004][S002]
Feature: Admin Reports & Financials
Step: Unified payment / receipt / installment record helpers
Logic: Build admin CRM payment rows; resolve onboarding coach; missing-receipt detection.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from .timezone import utc_to_hk

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from .models import Student

PaymentRecordStatus = Literal["paid", "outstanding", "missing_receipt"]


def payment_created_at_iso(dt: datetime | None) -> str:
    """[F004][S002] Serialize naive UTC ``created_at`` as Asia/Hong_Kong ISO (+08:00)."""
    if dt is None:
        return ""
    return utc_to_hk(dt).isoformat()

_ONBOARDING_COACH_RE = re.compile(r"Onboarding coach=([^\s,]+)", re.I)
_RENEWAL_CATEGORY_RE = re.compile(r"^\[([^\]]+)\]")


def extract_renewal_category_label(remarks: str | None) -> str | None:
    """[F004][S002] Parse ``[Category]`` prefix from regCourse renewal notes."""
    if not remarks:
        return None
    match = _RENEWAL_CATEGORY_RE.match(remarks.strip())
    return match.group(1).strip() if match else None


def build_renewal_payment_label(
    *,
    lessons: int,
    remarks: str | None,
    package_name: str | None = None,
) -> str:
    """[F004][S002] Human-readable renewal row label with course category when known."""
    category = package_name or extract_renewal_category_label(remarks)
    if category:
        rest = _RENEWAL_CATEGORY_RE.sub("", (remarks or "").strip(), count=1).strip()
        label = f"{lessons} 堂 · {category}"
        if rest:
            label += f" · {rest}"
        return label
    return f"{lessons} 堂 · {remarks or '報 Course / 續會'}"


def _coach_slug(full_name: str) -> str:
    slug = full_name.lower().replace(" ", "").replace("-", "")
    return "".join(c for c in slug if c.isalnum()) or "coach"


def student_onboarding_coach(db: Session, student_id: int) -> tuple[int | None, str | None]:
    """[F002][S001] Coach chosen at /register — from category enrollment notes or latest renewal."""
    from .models import AppUser, CategoryEnrollment, Coach, RenewalRecord

    def _resolve_coach_label(label: str) -> tuple[int | None, str | None]:
        if label.isdigit():
            coach = db.get(Coach, int(label))
            if coach:
                return coach.id, coach.full_name
        slug = label.lower()
        user = db.query(AppUser).filter(AppUser.username == slug).first()
        if user and user.coach_id:
            coach = db.get(Coach, int(user.coach_id))
            if coach:
                return coach.id, coach.full_name
        for coach in db.query(Coach).filter(Coach.active.is_(True)).all():
            if _coach_slug(coach.full_name) == slug:
                return coach.id, coach.full_name
        return None, None

    enrollments = (
        db.query(CategoryEnrollment)
        .filter(CategoryEnrollment.student_id == student_id)
        .filter(CategoryEnrollment.notes.isnot(None))
        .order_by(CategoryEnrollment.id.desc())
        .all()
    )
    for enr in enrollments:
        notes = enr.notes or ""
        match = _ONBOARDING_COACH_RE.search(notes)
        if not match:
            continue
        resolved = _resolve_coach_label(match.group(1).strip())
        if resolved[0] is not None:
            return resolved
    renewal = (
        db.query(RenewalRecord)
        .filter(RenewalRecord.student_id == student_id, RenewalRecord.coach_id.isnot(None))
        .order_by(RenewalRecord.id.desc())
        .first()
    )
    if renewal and renewal.coach_id:
        coach = db.get(Coach, renewal.coach_id)
        return renewal.coach_id, (coach.full_name if coach else renewal.coach_name)
    return None, None


def build_payment_records(
    db: Session,
    *,
    student_id: int | None = None,
    status: str | None = None,
    q: str | None = None,
    file_url_fn=None,
) -> list[dict]:
    """[F004][S002] Aggregate renewals, receipts, and category installment payments."""
    from sqlalchemy import select
    from sqlalchemy.orm import joinedload

    from .models import (
        CategoryEnrollment,
        DeletedRecord,
        InstallmentPlan,
        Package,
        Receipt,
        RenewalRecord,
        Student,
    )

    deleted_ids = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")
    deleted_renewal_ids = select(DeletedRecord.entity_id).where(
        DeletedRecord.entity_type == "renewal_records"
    )
    deleted_receipt_ids = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "receipts")
    students_q = db.query(Student).filter(~Student.id.in_(deleted_ids))
    if student_id is not None:
        students_q = students_q.filter(Student.id == student_id)
    students = {s.id: s for s in students_q.all()}
    if not students:
        return []

    student_ids = list(students.keys())
    rows: list[dict] = []

    renewals = (
        db.query(RenewalRecord)
        .filter(RenewalRecord.student_id.in_(student_ids))
        .filter(~RenewalRecord.id.in_(deleted_renewal_ids))
        .order_by(RenewalRecord.created_at.desc())
        .all()
    )
    receipt_ids = {r.receipt_id for r in renewals if r.receipt_id}
    receipt_map: dict[int, Receipt] = {}
    if receipt_ids:
        for rec in db.query(Receipt).filter(Receipt.id.in_(receipt_ids)).all():
            receipt_map[rec.id] = rec

    package_ids = {r.package_id for r in renewals if r.package_id}
    package_map: dict[int, Package] = {}
    if package_ids:
        for pkg in db.query(Package).filter(Package.id.in_(package_ids)).all():
            package_map[pkg.id] = pkg

    for rr in renewals:
        st = students.get(rr.student_id)
        if not st:
            continue
        rec = receipt_map.get(rr.receipt_id) if rr.receipt_id else None
        if rec:
            rec_status: PaymentRecordStatus = "paid"
        elif rr.amount and float(rr.amount) > 0:
            rec_status = "missing_receipt"
        else:
            rec_status = "outstanding"
        pkg = package_map.get(rr.package_id) if rr.package_id else None
        category_name = extract_renewal_category_label(rr.remarks) or (pkg.name if pkg else None)
        rows.append(
            {
                "id": f"renewal-{rr.id}",
                "record_type": "renewal",
                "ref_id": rr.id,
                "student_id": st.id,
                "student_name": st.full_name,
                "student_phone": st.phone,
                "amount": float(rr.amount) if rr.amount is not None else None,
                "payment_method": rr.payment_method,
                "status": rec_status,
                "coach_id": rr.coach_id,
                "coach_name": rr.coach_name,
                "label": build_renewal_payment_label(
                    lessons=int(rr.lessons),
                    remarks=rr.remarks,
                    package_name=pkg.name if pkg else None,
                ),
                "category_name": category_name,
                "receipt_id": rr.receipt_id,
                "receipt_url": file_url_fn(rec.file_path) if rec and file_url_fn else None,
                "created_at": payment_created_at_iso(rr.created_at),
            }
        )

    standalone_receipts = (
        db.query(Receipt)
        .filter(Receipt.student_id.in_(student_ids))
        .filter(~Receipt.id.in_(deleted_receipt_ids))
        .order_by(Receipt.created_at.desc())
        .all()
    )
    linked_receipt_ids = {r.receipt_id for r in renewals if r.receipt_id}
    for rec in standalone_receipts:
        if rec.id in linked_receipt_ids:
            continue
        st = students.get(rec.student_id)
        if not st:
            continue
        rows.append(
            {
                "id": f"receipt-{rec.id}",
                "record_type": "receipt",
                "ref_id": rec.id,
                "student_id": st.id,
                "student_name": st.full_name,
                "student_phone": st.phone,
                "amount": float(rec.amount) if rec.amount is not None else None,
                "payment_method": rec.payment_method,
                "status": "paid",
                "coach_id": None,
                "coach_name": None,
                "label": rec.note or rec.source or "收據",
                "receipt_id": rec.id,
                "receipt_url": file_url_fn(rec.file_path) if file_url_fn else None,
                "created_at": payment_created_at_iso(rec.created_at),
            }
        )

    cat_rows = (
        db.query(CategoryEnrollment)
        .options(
            joinedload(CategoryEnrollment.course_category),
            joinedload(CategoryEnrollment.installment_plans).joinedload(InstallmentPlan.payments),
        )
        .filter(CategoryEnrollment.student_id.in_(student_ids))
        .all()
    )
    for ce in cat_rows:
        st = students.get(ce.student_id)
        if not st:
            continue
        for plan in ce.installment_plans or []:
            if plan.status != "active":
                continue
            for pay in sorted(plan.payments or [], key=lambda p: p.installment_no):
                pay_status: PaymentRecordStatus = "paid" if pay.paid_at else "outstanding"
                rows.append(
                    {
                        "id": f"installment-{pay.id}",
                        "record_type": "installment",
                        "ref_id": pay.id,
                        "student_id": st.id,
                        "student_name": st.full_name,
                        "student_phone": st.phone,
                        "amount": float(pay.amount) if pay.amount else None,
                        "payment_method": None,
                        "status": pay_status,
                        "coach_id": None,
                        "coach_name": None,
                        "label": f"{ce.course_category.name} · 分期第{pay.installment_no}期",
                        "installment_no": pay.installment_no,
                        "installment_plan_id": plan.id,
                        "category_enrollment_id": ce.id,
                        "due_date": pay.due_date.isoformat() if pay.due_date else None,
                        "paid_at": pay.paid_at.isoformat() if pay.paid_at else None,
                        "receipt_id": None,
                        "receipt_url": None,
                        "created_at": payment_created_at_iso(
                            pay.paid_at or pay.due_date or ce.started_at
                        ),
                    }
                )

    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)

    if status:
        norm = status.strip().lower()
        if norm in {"missing_receipt", "missing-receipt"}:
            rows = [r for r in rows if r["status"] == "missing_receipt"]
        elif norm == "outstanding":
            rows = [r for r in rows if r["status"] == "outstanding"]
        elif norm == "paid":
            rows = [r for r in rows if r["status"] == "paid"]

    if q and q.strip():
        needle = q.strip().lower()
        rows = [
            r
            for r in rows
            if needle in (r.get("student_name") or "").lower()
            or needle in (r.get("student_phone") or "")
            or needle in (r.get("label") or "").lower()
        ]

    return rows


def build_sales_report_rows(db: Session) -> list[dict]:
    """[F004][S001] Map unified payment records to monthly sales report row shape."""
    rows: list[dict] = []
    for r in build_payment_records(db, file_url_fn=None):
        status = str(r.get("status") or "")
        if status == "paid":
            pay = "已付"
        elif status == "missing_receipt":
            pay = "缺收據"
        elif status == "outstanding":
            pay = "待付"
        else:
            pay = status.upper() if status else "—"
        if r.get("record_type") == "installment":
            inst = "進行中" if status == "outstanding" else ("已付" if status == "paid" else "—")
        elif r.get("installment_no"):
            inst = f"第{r['installment_no']}期"
        else:
            inst = "無"
        created = str(r.get("created_at") or "")
        date_part = created[:10] if len(created) >= 10 else created
        rows.append(
            {
                "date": date_part,
                "clientName": r.get("student_name") or "",
                "courseType": r.get("label") or "",
                "amount": float(r.get("amount") or 0),
                "coachName": r.get("coach_name") or "—",
                "paymentStatus": pay,
                "installmentStatus": inst,
            }
        )
    return rows


def count_missing_receipt_renewals(db: Session) -> int:
    """[F004][S002] Renewals with amount but no receipt file linked."""
    from sqlalchemy import select

    from .models import DeletedRecord, RenewalRecord

    deleted_ids = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")
    return (
        db.query(RenewalRecord)
        .filter(~RenewalRecord.student_id.in_(deleted_ids))
        .filter(RenewalRecord.receipt_id.is_(None))
        .filter(RenewalRecord.amount.isnot(None))
        .filter(RenewalRecord.amount > 0)
        .count()
    )
