"""[F005][S003] Course-scoped payment facts for the four client-approved templates."""

import json
import math

from fastapi import HTTPException


def course_payment_state(enrollment) -> dict:
    """[F005][S003] Read saved course facts without borrowing another course's receipts."""
    raw = getattr(enrollment, "payment_state_json", None) if enrollment else None
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def record_course_payment(enrollment, *, amount, total_amount=None, installment_no=None,
                          full_payment=False, received=True, renewal_id=None, receipt_id=None) -> dict:
    """[F004][S002] Save one payment per installment; replacing its receipt does not double-count it."""
    state = course_payment_state(enrollment)
    segments = json.loads(enrollment.segment_pins_json or "[]")
    if total_amount is None:
        total_amount = state.get("total_amount")
    if total_amount is None and segments and all(s.get("amount_hkd") is not None for s in segments):
        total_amount = sum(float(s["amount_hkd"]) for s in segments)
    if total_amount is not None and (not math.isfinite(float(total_amount)) or float(total_amount) <= 0):
        raise HTTPException(status_code=400, detail="Invalid course total amount.")
    if amount is not None and (not math.isfinite(float(amount)) or float(amount) < 0):
        raise HTTPException(status_code=400, detail="Invalid payment amount.")
    payments = dict(state.get("payments") or {})
    confirmed = bool(received and amount is not None and float(amount) > 0)
    if confirmed:
        key = f"installment:{installment_no}" if segments and not full_payment and installment_no else "full"
        payments[key] = {"amount": round(float(amount), 2), "receipt_id": receipt_id}
    paid = round(sum(float(p["amount"]) for p in payments.values()), 2)
    total = round(float(total_amount), 2) if total_amount is not None else None
    if full_payment and total is not None and paid + 0.005 < total:
        raise HTTPException(status_code=400, detail="Full payment does not cover the course balance.")
    state.update({"payments": payments, "total_amount": total,
                  "paid_total": paid, "last_amount": round(float(amount), 2) if confirmed else state.get("last_amount"),
                  "confirmed": bool(payments), "fully_paid": bool(total is not None and paid + 0.005 >= total)})
    state["receipt_uploaded"] = any(p.get("receipt_id") is not None for p in payments.values())
    if confirmed and installment_no is not None:
        state["last_installment_no"] = installment_no
    if renewal_id is not None:
        state["renewal_id"] = renewal_id
    for segment in segments:
        key = f"installment:{segment['installment_no']}"
        installment_paid = float(payments.get(key, {}).get("amount", 0))
        expected = segment.get("amount_hkd")
        segment["paid"] = state["fully_paid"] or (installment_paid > 0 and (expected is None or installment_paid + 0.005 >= float(expected)))
    if segments:
        enrollment.segment_pins_json = json.dumps(segments, ensure_ascii=False)
    enrollment.payment_state_json = json.dumps(state, ensure_ascii=False)
    return state
