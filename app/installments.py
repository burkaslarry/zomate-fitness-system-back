"""[F004][S003]
Feature: Admin Reports & Financials
Step: Unified installment ledger for dashboard KPIs and 分期付款學生 board
Logic: Merge course segment-PIN installments with category InstallmentPlan rows so admin counts
       match the money staff see in 付款紀錄 instead of only the category-plan table.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from .course_payment_state import course_payment_state

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def _as_float(value) -> float | None:
    """[F004][S003] Numeric/Decimal/str → float; never invent a missing amount."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _segment_paid(segment: dict) -> bool:
    """[F004][S003] Match PIN gating: legacy rows without `paid` treat the first tranche as paid."""
    raw = segment.get("paid")
    if raw is None:
        return int(segment.get("installment_no") or 0) <= 1
    return bool(raw)


def _course_periods(enr, paid_at_by_receipt: dict[int, str]) -> list[dict]:
    """[F004][S003] Build one period per course installment segment (never a single full payment)."""
    try:
        segments = json.loads(enr.segment_pins_json or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(segments, list):
        return []
    payments = course_payment_state(enr).get("payments") or {}
    periods: list[dict] = []
    for segment in sorted(
        (s for s in segments if isinstance(s, dict)), key=lambda s: int(s.get("installment_no") or 0)
    ):
        try:
            no = int(segment.get("installment_no") or 0)
        except (TypeError, ValueError):
            continue
        if no < 1:
            continue
        paid = _segment_paid(segment)
        receipt_id = (payments.get(f"installment:{no}") or {}).get("receipt_id")
        periods.append(
            {
                "installment_no": no,
                "amount": _as_float(segment.get("amount_hkd")),
                "paid": paid,
                "paid_at": paid_at_by_receipt.get(int(receipt_id)) if receipt_id else None,
                "due_date": None,
                "lesson_from": segment.get("lesson_from"),
                "lesson_to": segment.get("lesson_to"),
            }
        )
    return periods


def _category_periods(plan) -> list[dict]:
    """[F004][S003] Category plans already store one row per due period."""
    return [
        {
            "installment_no": pay.installment_no,
            "amount": _as_float(pay.amount),
            "paid": pay.paid_at is not None,
            "paid_at": pay.paid_at.isoformat() if pay.paid_at else None,
            "due_date": pay.due_date.isoformat() if pay.due_date else None,
            "lesson_from": None,
            "lesson_to": None,
        }
        for pay in sorted(plan.payments or [], key=lambda p: p.installment_no)
    ]


def _summarize_row(row: dict) -> dict:
    """[F004][S003] Derive progress fields from periods so both sources share one contract."""
    periods = row["periods"]
    paid_periods = [p for p in periods if p["paid"]]
    unpaid_periods = [p for p in periods if not p["paid"]]
    paid_amount = sum(p["amount"] or 0 for p in paid_periods)
    outstanding = sum(p["amount"] or 0 for p in unpaid_periods)
    has_amounts = any(p["amount"] is not None for p in periods)
    total_amount = paid_amount + outstanding if has_amounts else None
    next_period = min(unpaid_periods, key=lambda p: p["installment_no"]) if unpaid_periods else None
    row.update(
        {
            "total_installments": len(periods),
            "paid_installments": len(paid_periods),
            "unpaid_installments": len(unpaid_periods),
            "total_amount": round(total_amount, 2) if total_amount is not None else None,
            "paid_amount": round(paid_amount, 2),
            "outstanding_amount": round(outstanding, 2),
            "next_installment_no": next_period["installment_no"] if next_period else None,
            "next_due_date": next_period["due_date"] if next_period else None,
            "status": "completed" if periods and not unpaid_periods else "active",
        }
    )
    return row


def build_installment_ledger(db: Session, *, student_id: int | None = None) -> list[dict]:
    """[F004][S003] All installment-bearing enrollments for admin reporting."""
    from .models import (
        Branch,
        CategoryEnrollment,
        CourseEnrollment,
        DeletedRecord,
        InstallmentPlan,
        Receipt,
    )

    deleted_students = select(DeletedRecord.entity_id).where(
        DeletedRecord.entity_type == "students"
    )
    deleted_courses = select(DeletedRecord.entity_id).where(
        DeletedRecord.entity_type == "course_enrollments"
    )
    deleted_receipts = select(DeletedRecord.entity_id).where(
        DeletedRecord.entity_type == "receipts"
    )
    deleted_student_ids = set(db.execute(deleted_students).scalars().all())

    branch_map = {b.id: b for b in db.query(Branch).all()}

    def branch_fields(branch_id: int | None) -> dict:
        branch = branch_map.get(int(branch_id)) if branch_id else None
        return {
            "branch_id": int(branch_id) if branch_id else None,
            "branch_name": branch.name if branch else None,
            "branch_code": branch.code if branch else None,
        }

    courses_q = (
        db.query(CourseEnrollment)
        .options(
            joinedload(CourseEnrollment.student),
            joinedload(CourseEnrollment.coach),
        )
        .filter(~CourseEnrollment.id.in_(deleted_courses))
        .filter(~CourseEnrollment.student_id.in_(deleted_students))
        .filter(CourseEnrollment.segment_pins_json.isnot(None))
    )
    if student_id is not None:
        courses_q = courses_q.filter(CourseEnrollment.student_id == student_id)
    courses = courses_q.all()

    receipt_ids: set[int] = set()
    for enr in courses:
        for payment in (course_payment_state(enr).get("payments") or {}).values():
            receipt_id = payment.get("receipt_id")
            if receipt_id:
                receipt_ids.add(int(receipt_id))
    paid_at_by_receipt: dict[int, str] = {}
    if receipt_ids:
        for receipt in (
            db.query(Receipt)
            .filter(Receipt.id.in_(receipt_ids))
            .filter(~Receipt.id.in_(deleted_receipts))
            .all()
        ):
            if receipt.created_at:
                paid_at_by_receipt[receipt.id] = receipt.created_at.isoformat()

    rows: list[dict] = []
    for enr in courses:
        periods = _course_periods(enr, paid_at_by_receipt)
        if len(periods) < 2:
            # A one-payment course is a full payment, not an installment plan.
            continue
        student = enr.student
        if student is None or student.id in deleted_student_ids:
            continue
        rows.append(
            _summarize_row(
                {
                    "id": f"course-{enr.id}",
                    "source": "course",
                    "source_id": enr.id,
                    "course_enrollment_id": enr.id,
                    "category_enrollment_id": None,
                    "installment_plan_id": None,
                    "student_id": student.id,
                    "student_name": student.full_name,
                    "student_phone": student.phone,
                    "label": enr.title or "Course",
                    "coach_name": enr.coach.full_name if enr.coach else None,
                    **branch_fields(enr.branch_id or student.branch_id),
                    "periods": periods,
                }
            )
        )

    plans_q = (
        db.query(InstallmentPlan)
        .options(
            joinedload(InstallmentPlan.enrollment).joinedload(CategoryEnrollment.student),
            joinedload(InstallmentPlan.enrollment).joinedload(CategoryEnrollment.course_category),
            joinedload(InstallmentPlan.payments),
        )
        .filter(InstallmentPlan.status == "active")
    )
    if student_id is not None:
        plans_q = plans_q.filter(
            InstallmentPlan.enrollment.has(CategoryEnrollment.student_id == student_id)
        )
    for plan in plans_q.all():
        enrollment = plan.enrollment
        if enrollment is None or enrollment.student is None:
            continue
        if enrollment.student_id in deleted_student_ids:
            continue
        periods = _category_periods(plan)
        if not periods:
            continue
        student = enrollment.student
        category_name = (
            enrollment.course_category.name if enrollment.course_category else "課程種類"
        )
        rows.append(
            _summarize_row(
                {
                    "id": f"category-{plan.id}",
                    "source": "category",
                    "source_id": plan.id,
                    "course_enrollment_id": None,
                    "category_enrollment_id": enrollment.id,
                    "installment_plan_id": plan.id,
                    "student_id": student.id,
                    "student_name": student.full_name,
                    "student_phone": student.phone,
                    "label": category_name,
                    "coach_name": None,
                    **branch_fields(student.branch_id),
                    "periods": periods,
                }
            )
        )

    rows.sort(
        key=lambda r: (
            r["unpaid_installments"] == 0,
            -r["unpaid_installments"],
            r["student_name"] or "",
            r["label"] or "",
        )
    )
    return rows


def summarize_installments(rows: list[dict]) -> dict:
    """[F004][S003] Dashboard totals: periods to follow up, students, and unpaid money."""
    return {
        "students_total": len({r["student_id"] for r in rows}),
        "students_unpaid": len({r["student_id"] for r in rows if r["unpaid_installments"] > 0}),
        "periods_total": sum(r["total_installments"] for r in rows),
        "periods_unpaid": sum(r["unpaid_installments"] for r in rows),
        "periods_paid": sum(r["paid_installments"] for r in rows),
        "outstanding_amount": round(sum(r["outstanding_amount"] or 0 for r in rows), 2),
    }
