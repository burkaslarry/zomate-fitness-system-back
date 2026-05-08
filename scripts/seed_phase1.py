#!/usr/bin/env python3
"""Seed CourseCategory rows (idempotent). Run after migrations."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import CourseCategory

DEFAULT_CATEGORIES = [
    "新學生一對一",
    "新學生一對二",
    "續會學生一對一",
    "續會學生一對二",
    "自帶學生一對一",
    "自帶學生一對二",
]


def run(db: Session) -> None:
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
