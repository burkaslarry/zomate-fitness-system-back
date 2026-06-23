"""[F005][S003]
Feature: Balance Sync & Integrations
Step: WhatsApp payment reminder templates
Logic: Seed, render, and select admin-editable message templates for student/coach payment notifications.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from .models import Coach, CourseEnrollment, InstallmentPayment, Student, WhatsAppMessageTemplate

PaymentTemplateKey = Literal[
    "payment_student_pending",
    "payment_student_installment",
    "payment_student_full",
    "payment_coach",
]

DEFAULT_WHATSAPP_TEMPLATES: list[dict[str, str]] = [
    {
        "key": "payment_student_pending",
        "audience": "student",
        "title": "收據未確認（學生）",
        "body": """收據未確認
【Zomate 開課】{{course_title}}
{{student_name}}（{{student_phone}}）
課堂 PIN：{{pin}}
上堂時間 : {{next_lesson_date}}
已上堂數: {{lessons_attended}}
餘下堂數: {{lessons_remaining}}
公司有待確認付款""",
    },
    {
        "key": "payment_student_installment",
        "audience": "student",
        "title": "收據已上傳 · 分期（學生）",
        "body": """收據已上傳 (分期)
【Zomate 開課】{{course_title}}
{{student_name}}（{{student_phone}}）
課堂 PIN：{{pin}}
上堂時間 : {{next_lesson_date}}
已上堂數: {{lessons_attended}}
餘下堂數: {{lessons_remaining}}
付款狀態: {{payment_status}}
已付金額: {{amount_paid}}
總數 : {{total_amount}}
尚欠: {{amount_owing}}
{{installment_notes}}""",
    },
    {
        "key": "payment_student_full",
        "audience": "student",
        "title": "收據已上傳 · 全數（學生）",
        "body": """收據已上傳 (full pay)
【Zomate 開課】{{course_title}}
{{student_name}}（{{student_phone}}）
課堂 PIN：{{pin}}
上堂時間 : {{next_lesson_date}}
已上堂數: {{lessons_attended}}
餘下堂數: {{lessons_remaining}}
付款狀態: {{payment_status}}
已付金額: {{amount_paid}}
總數 : {{total_amount}}""",
    },
    {
        "key": "payment_coach",
        "audience": "coach",
        "title": "開課／付款通知（教練）",
        "body": """【Zomate 開課】{{course_title}}
{{student_name}}（{{student_phone}}）

上堂時間 : {{next_lesson_date}}
已上堂數: {{lessons_attended}}
餘下堂數: {{lessons_remaining}}
付款狀態: {{payment_status}}
已付金額: {{amount_paid}}
總數 : {{total_amount}}
尚欠: {{amount_owing}}
{{installment_notes}}""",
    },
]

_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")


def render_whatsapp_template(body: str, context: dict[str, str]) -> str:
    """[F005][S003] Replace {{key}} placeholders; unknown keys become empty strings."""

    def repl(match: re.Match[str]) -> str:
        return context.get(match.group(1), "")

    return _PLACEHOLDER_RE.sub(repl, body).strip()


def seed_whatsapp_templates(db: Session) -> None:
    """[F005][S003] Insert default templates when table is empty or missing keys."""
    from .models import WhatsAppMessageTemplate

    existing = {row.key for row in db.query(WhatsAppMessageTemplate.key).all()}
    for row in DEFAULT_WHATSAPP_TEMPLATES:
        if row["key"] in existing:
            continue
        db.add(
            WhatsAppMessageTemplate(
                key=row["key"],
                audience=row["audience"],
                title=row["title"],
                body=row["body"],
            )
        )


def get_template_body(db: Session, key: str) -> str:
    """[F005][S003] Load template body from DB or fall back to bundled defaults."""
    from .models import WhatsAppMessageTemplate

    row = db.query(WhatsAppMessageTemplate).filter(WhatsAppMessageTemplate.key == key).first()
    if row:
        return row.body
    for default in DEFAULT_WHATSAPP_TEMPLATES:
        if default["key"] == key:
            return default["body"]
    return ""


def _fmt_hkd(amount: float | None) -> str:
    if amount is None:
        return "—"
    if float(amount).is_integer():
        return f"HKD {int(amount)}"
    return f"HKD {amount:g}"


def _display_phone(phone: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    if len(digits) == 11 and digits.startswith("852"):
        return digits[3:]
    if len(digits) == 8:
        return digits
    return phone.strip()


def _ordinal_en(n: int) -> str:
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def build_installment_notes_from_segments(segments: list[dict]) -> str:
    """[F005][S003] e.g. 第A堂付 2nd instalment for unpaid future tranches."""
    lines: list[str] = []
    for seg in segments:
        if not isinstance(seg, dict):
            continue
        if seg.get("paid"):
            continue
        ino = int(seg.get("installment_no") or 0)
        lo = int(seg.get("lesson_from") or 0)
        if ino <= 1 or lo <= 0:
            continue
        lesson_label = chr(ord("A") + min(ino - 2, 25))
        lines.append(f"第{lesson_label}堂付 {_ordinal_en(ino)} instalment")
    return "\n".join(lines)


def resolve_payment_template_key(
    *,
    receipt_confirmed: bool,
    is_installment: bool,
    audience: Literal["student", "coach"],
) -> PaymentTemplateKey:
    """[F005][S003] Pick template key from payment/receipt state."""
    if audience == "coach":
        return "payment_coach"
    if not receipt_confirmed:
        return "payment_student_pending"
    if is_installment:
        return "payment_student_installment"
    return "payment_student_full"


def build_payment_context(
    *,
    student: Student,
    course_title: str,
    pin: str,
    next_lesson_date: str,
    lessons_attended: int,
    lessons_remaining: int,
    payment_status: str,
    amount_paid: float | None,
    total_amount: float | None,
    amount_owing: float | None,
    installment_notes: str,
) -> dict[str, str]:
    """[F005][S003] Context map for template rendering."""
    return {
        "course_title": course_title or "—",
        "student_name": student.full_name,
        "student_phone": _display_phone(student.phone),
        "pin": pin or "—",
        "next_lesson_date": next_lesson_date or "—",
        "lessons_attended": str(max(0, lessons_attended)),
        "lessons_remaining": str(max(0, lessons_remaining)),
        "payment_status": payment_status,
        "amount_paid": _fmt_hkd(amount_paid),
        "total_amount": _fmt_hkd(total_amount),
        "amount_owing": _fmt_hkd(amount_owing),
        "installment_notes": installment_notes.strip(),
    }


def sum_receipt_amounts(receipts: list) -> float:
    total = 0.0
    for r in receipts:
        amt = getattr(r, "amount", None)
        if amt is not None:
            total += float(amt)
    return total


def sum_installment_paid_amount(payments: list[InstallmentPayment]) -> float:
    total = 0.0
    for pay in payments:
        if pay.paid_at is not None or pay.status.lower() == "paid":
            total += float(pay.amount or 0)
    return total


def derive_payment_amounts(
    *,
    receipt_amount: float | None,
    total_receipts: float,
    installment_payments: list[InstallmentPayment] | None,
    renewal_amount: float | None,
    is_installment: bool,
) -> tuple[float | None, float | None, float | None]:
    """[F005][S003] Return (paid, total, owing) best-effort from available records."""
    paid = receipt_amount if receipt_amount is not None else total_receipts
    if paid <= 0 and installment_payments:
        inst_paid = sum_installment_paid_amount(installment_payments)
        if inst_paid > 0:
            paid = inst_paid
    if paid <= 0 and renewal_amount is not None:
        paid = float(renewal_amount)
    total = renewal_amount if renewal_amount is not None else paid
    if is_installment and installment_payments:
        inst_total = sum(float(p.amount or 0) for p in installment_payments)
        if inst_total > 0:
            total = inst_total
    owing = max(0.0, float(total or 0) - float(paid or 0)) if is_installment else 0.0
    return paid or None, total or None, owing if is_installment else None


def format_lesson_datetime(enr: CourseEnrollment | None) -> str:
    if enr is None or enr.scheduled_start is None:
        return "—"
    return enr.scheduled_start.strftime("%Y-%m-%d %H:%M")


def count_course_checkins(db: Session, student_id: int, course_id: int | None) -> int:
    from .models import Attendance

    if course_id is None:
        return 0
    return (
        db.query(Attendance)
        .filter(
            Attendance.student_id == student_id,
            Attendance.course_id == course_id,
        )
        .count()
    )
