"""[F007][S004]
Feature: Backend platform (FastAPI & PostgreSQL)
Step: (see Logic)
Logic: Phase-1 domain seed script.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import CategoryEnrollment, CoachSkill, CourseCategory, InstallmentPayment, InstallmentPlan

DEFAULT_CATEGORIES = [
    "新學生一對一",
    "新學生一對二",
    "續會學生一對一",
    "續會學生一對二",
    "自帶學生一對一",
    "自帶學生一對二",
    "Yoga 瑜珈",
    "Stretching 拉伸",
    "Pilates 普拉提",
    "Thai Boxing",
    "紮肚",
    "Group Class",
    "1:1 Pilates 4堂",
]

HARD_DELETE_CATEGORIES = ("泰拳一對一", "泰拳一對二")


def _hard_delete_category(db: Session, name: str) -> None:
    cat = db.query(CourseCategory).filter(CourseCategory.name == name).first()
    if cat is None:
        return
    db.query(CoachSkill).filter(CoachSkill.course_category_id == cat.id).delete(synchronize_session=False)
    for en in db.query(CategoryEnrollment).filter(CategoryEnrollment.course_category_id == cat.id).all():
        for plan in db.query(InstallmentPlan).filter(InstallmentPlan.enrollment_id == en.id).all():
            db.query(InstallmentPayment).filter(InstallmentPayment.installment_plan_id == plan.id).delete(
                synchronize_session=False
            )
            db.delete(plan)
        db.delete(en)
    db.flush()
    db.delete(cat)


def run(db: Session) -> None:
    for name in HARD_DELETE_CATEGORIES:
        _hard_delete_category(db, name)
    for name in DEFAULT_CATEGORIES:
        row = db.query(CourseCategory).filter(CourseCategory.name == name).first()
        if row:
            row.is_deleted = False
            row.is_active = True
            continue
        db.add(
            CourseCategory(
                name=name,
                is_active=True,
                is_deleted=False,
                created_by_role="admin",
            )
        )
    db.commit()


def main() -> None:
    db = SessionLocal()
    try:
        run(db)
        print("seed_phase1_ok")
    finally:
        db.close()


if __name__ == "__main__":
    main()
