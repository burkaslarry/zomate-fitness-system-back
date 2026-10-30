"""[F004][S008] Installment ledger + 簽到次數 dashboard counts."""

import json
from datetime import date, datetime

from app import main
from app.installments import build_installment_ledger, summarize_installments
from app.models import (
    Branch,
    CategoryEnrollment,
    CheckinLog,
    Coach,
    CourseCategory,
    CourseEnrollment,
    DeletedRecord,
    InstallmentPayment,
    InstallmentPlan,
    Receipt,
    Student,
)


def _seed(db):
    """[F004][S008] One course plan (3 periods) + one category plan (2 periods) + a deleted student."""
    branch = Branch(name="TST", code="TST", address="Test")
    coach = Coach(full_name="Coach Fung", phone="91230000", branch=branch, active=True)
    alice = Student(full_name="Alice Wong", phone="91110001", branch=branch)
    bob = Student(full_name="Bob Lee", phone="91110002", branch=branch)
    gone = Student(full_name="Gone Chan", phone="91110003", branch=branch)
    db.add_all([branch, coach, alice, bob, gone])
    db.flush()

    receipt = Receipt(
        student_id=alice.id,
        member_hkid="A1234567",
        file_path="receipts/A1234567/fps.png",
        amount=3000,
        source="RENEWAL",
        created_at=datetime(2026, 10, 5, 4, 0),
    )
    db.add(receipt)
    db.flush()

    db.add(
        CourseEnrollment(
            title="Pilates",
            branch_id=branch.id,
            coach_id=coach.id,
            student_id=alice.id,
            scheduled_start=datetime(2026, 10, 6, 10),
            scheduled_end=datetime(2026, 10, 6, 11),
            checkin_pin="11111",
            total_lessons=30,
            segment_pins_json=json.dumps(
                [
                    {"installment_no": 1, "lesson_from": 1, "lesson_to": 10, "pin": "11111", "paid": True, "amount_hkd": 3000},
                    {"installment_no": 2, "lesson_from": 11, "lesson_to": 20, "pin": "", "paid": False, "amount_hkd": 3000},
                    {"installment_no": 3, "lesson_from": 21, "lesson_to": 30, "pin": "", "paid": False},
                ]
            ),
            payment_state_json=json.dumps(
                {"payments": {"installment:1": {"amount": 3000, "receipt_id": receipt.id}}}
            ),
        )
    )
    category = CourseCategory(name="Yoga")
    db.add(category)
    db.flush()
    enrollment = CategoryEnrollment(
        student_id=bob.id,
        course_category_id=category.id,
        started_at=date(2026, 10, 1),
        total_lessons=10,
    )
    db.add(enrollment)
    db.flush()
    plan = InstallmentPlan(enrollment_id=enrollment.id, total_installments=2, status="active")
    db.add(plan)
    db.flush()
    db.add_all(
        [
            InstallmentPayment(
                installment_plan_id=plan.id,
                installment_no=1,
                amount=1000,
                due_date=date(2026, 10, 1),
                paid_at=datetime(2026, 10, 2),
                status="paid",
            ),
            InstallmentPayment(
                installment_plan_id=plan.id,
                installment_no=2,
                amount=1000,
                due_date=date(2026, 11, 1),
                status="pending",
            ),
        ]
    )

    db.add(
        CourseEnrollment(
            title="Deleted course",
            branch_id=branch.id,
            coach_id=coach.id,
            student_id=gone.id,
            scheduled_start=datetime(2026, 10, 6, 10),
            scheduled_end=datetime(2026, 10, 6, 11),
            checkin_pin="22222",
            total_lessons=20,
            segment_pins_json=json.dumps(
                [
                    {"installment_no": 1, "lesson_from": 1, "lesson_to": 10, "pin": "22222", "paid": False},
                    {"installment_no": 2, "lesson_from": 11, "lesson_to": 20, "pin": "", "paid": False},
                ]
            ),
        )
    )
    db.add(DeletedRecord(entity_type="students", entity_id=gone.id))
    db.commit()
    return alice, bob


def test_ledger_merges_course_and_category_installments(db_session):
    """[F004][S008] Course seg-PIN periods and category plan periods share one contract."""
    alice, bob = _seed(db_session)

    rows = build_installment_ledger(db_session)
    assert len(rows) == 2
    course = next(r for r in rows if r["source"] == "course")
    category = next(r for r in rows if r["source"] == "category")

    assert course["student_id"] == alice.id
    assert course["total_installments"] == 3
    assert course["paid_installments"] == 1
    assert course["unpaid_installments"] == 2
    assert course["paid_amount"] == 3000
    assert course["outstanding_amount"] == 3000
    assert course["total_amount"] == 6000
    assert course["next_installment_no"] == 2
    assert course["periods"][0]["paid_at"] is not None  # receipt date, not invented
    assert course["branch_code"] == "TST"

    assert category["student_id"] == bob.id
    assert category["total_installments"] == 2
    assert category["paid_installments"] == 1
    assert category["outstanding_amount"] == 1000

    assert all(r["student_id"] != alice.id or r["source"] == "course" for r in rows)
    assert all("Gone" not in r["student_name"] for r in rows)


def test_ledger_summary_counts_periods_and_students(db_session):
    """[F004][S008] Dashboard totals must not be 0 when installments exist."""
    _seed(db_session)

    summary = summarize_installments(build_installment_ledger(db_session))
    assert summary == {
        "students_total": 2,
        "students_unpaid": 2,
        "periods_total": 5,
        "periods_unpaid": 3,
        "periods_paid": 2,
        "outstanding_amount": 4000,
    }


def test_admin_summary_exposes_installment_periods_and_checkins(db_session):
    """[F004][S008] Admin dashboard reads the ledger and HK check-in windows."""
    _seed(db_session)

    payload = main.admin_summary(db=db_session, user=None)
    assert payload["installment_students_total"] == 2
    assert payload["installment_students_unpaid"] == 2
    assert payload["installment_periods_total"] == 5
    assert payload["installment_periods_unpaid"] == 3
    assert payload["installment_outstanding_amount"] == 4000
    assert "checkins_today" in payload
    assert "checkins_this_month" in payload
    assert len(payload["checkins_last_7_days"]) == 7


def test_admin_installments_filters_unpaid_but_keeps_summary(db_session):
    """[F004][S008] The board filter narrows rows only."""
    _seed(db_session)

    payload = main.admin_installments(only_unpaid=True, db=db_session, user=None)
    assert len(payload["rows"]) == 2
    assert all(r["unpaid_installments"] > 0 for r in payload["rows"])
    assert payload["summary"]["periods_total"] == 5


def test_checkin_counts_use_hk_day_and_month_boundaries(db_session):
    """[F004][S008] 00:30 HKT counts today; 23:59 HKT yesterday does not."""
    _seed(db_session)
    student_id = db_session.query(Student.id).order_by(Student.id).first()[0]
    db_session.add_all(
        [
            CheckinLog(student_id=student_id, created_at=datetime(2026, 3, 14, 16, 30)),  # 15/03 00:30 HKT
            CheckinLog(student_id=student_id, created_at=datetime(2026, 3, 14, 15, 59)),  # 14/03 23:59 HKT
            CheckinLog(student_id=student_id, created_at=datetime(2026, 2, 28, 16, 5)),  # 01/03 00:05 HKT
            CheckinLog(student_id=student_id, created_at=datetime(2026, 2, 28, 15, 55)),  # 28/02 23:55 HKT
            CheckinLog(student_id=student_id, created_at=datetime(2026, 3, 9, 4, 0)),  # 09/03 12:00 HKT
        ]
    )
    db_session.commit()

    stats = main._checkin_counts(db_session, date(2026, 3, 15))
    assert stats["today"] == 1
    assert stats["month"] == 4
    assert stats["last_7_days"] == [
        {"date": "2026-03-09", "count": 1},
        {"date": "2026-03-10", "count": 0},
        {"date": "2026-03-11", "count": 0},
        {"date": "2026-03-12", "count": 0},
        {"date": "2026-03-13", "count": 0},
        {"date": "2026-03-14", "count": 1},
        {"date": "2026-03-15", "count": 1},
    ]
