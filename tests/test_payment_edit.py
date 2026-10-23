"""[F004][S002] Audited payment editing never silently changes confirmation or sends WhatsApp."""
import json
from datetime import datetime, date
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
from app import main
from app.models import AuditLog, RenewalRecord
from app.schemas import PaymentRecordUpdate
from test_client_payment_flow import _course


def _renewal(db):
    """[F007][S005] Isolated pending renewal linked to exactly one course."""
    student, coach, enr = _course(db)
    row = RenewalRecord(student_id=student.id, student_name=student.full_name, phone=student.phone,
        course_ratio="1:1", lessons=30, payment_method="fps", amount=3000, remarks="[Pilates] QA",
        applicant_name="QA", signature="QA", renewal_date=date(2026,10,23))
    db.add(row); db.flush()
    enr.payment_state_json = json.dumps({"renewal_id":row.id,"pending_payments":{"1":{"amount":3000}}})
    db.commit()
    return row, enr


def test_pending_amount_metadata_saved_audited_and_course_updated(db_session):
    """[F004][S002] Reload returns edited values while pending funds stay unconfirmed."""
    row, enr = _renewal(db_session)
    result = main.admin_update_payment_record("renewal", row.id,
        PaymentRecordUpdate(amount=3200, payment_method="cash", note="QA corrected", created_at=datetime(2026,10,23,7)),
        db_session, SimpleNamespace(username="qa-admin"))
    assert result["record"]["amount"] == 3200
    assert result["record"]["payment_method"] == "cash"
    assert result["record"]["note"] == "QA corrected"
    assert json.loads(enr.payment_state_json)["pending_payments"]["1"]["amount"] == 3200
    assert db_session.query(AuditLog).filter_by(action="payment_record_edit").count() == 1


def test_confirmed_amount_rejected_but_notes_allowed(db_session):
    """[F004][S002] No edit can silently invalidate already-confirmed funds and PIN eligibility."""
    row, enr = _renewal(db_session)
    enr.payment_state_json = json.dumps({"renewal_id":row.id, "payments":{"installment:1":{"amount":3000}}})
    db_session.commit()
    with pytest.raises(HTTPException) as exc:
        main.admin_update_payment_record("renewal", row.id, PaymentRecordUpdate(amount=1), db_session, SimpleNamespace(username="qa"))
    assert exc.value.status_code == 409
    assert float(row.amount) == 3000
    result = main.admin_update_payment_record("renewal", row.id, PaymentRecordUpdate(note="Metadata only"), db_session, SimpleNamespace(username="qa"))
    assert result["record"]["note"] == "Metadata only"


@pytest.mark.parametrize("payload", [{"amount":-1},{"amount":float('nan')},{"status":"paid"},{"student_id":2}])
def test_edit_rejects_invalid_or_unscoped_fields(payload):
    """[F004][S002] Financial and identity fields cannot be smuggled through arbitrary JSON."""
    with pytest.raises(ValidationError): PaymentRecordUpdate(**payload)


def test_edit_route_rejects_coach_before_db():
    """[F004][S002] Coach cannot use the Admin correction endpoint."""
    main.app.dependency_overrides[main.get_current_user] = lambda: SimpleNamespace(role="COACH", username="qa")
    try:
        with TestClient(main.app) as client:
            assert client.patch('/api/admin/payment-records/renewal/1',json={"amount":1}).status_code == 403
    finally: main.app.dependency_overrides.clear()


def test_pending_view_cannot_rewrite_partially_confirmed_renewal(db_session):
    """[F004][S002] A pending next tranche must not make an earlier confirmed renewal amount editable."""
    row, enr = _renewal(db_session)
    state = json.loads(enr.payment_state_json)
    state["payments"] = {"installment:1": {"amount":3000}}
    state["pending_payments"] = {"2": {"amount":1000}}
    enr.payment_state_json = json.dumps(state)
    db_session.commit()
    with pytest.raises(HTTPException) as exc:
        main.admin_update_payment_record("renewal", row.id, PaymentRecordUpdate(amount=500), db_session, SimpleNamespace(username="qa"))
    assert exc.value.status_code == 409
    assert float(row.amount) == 3000
    assert json.loads(enr.payment_state_json) == state
