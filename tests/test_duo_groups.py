"""[F002][S003] 1-on-2 shared package helpers."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.duo_groups import is_duo_course_category, _hk_local_eight
from app.models import CourseCategory


def test_is_duo_course_category_names():
  assert is_duo_course_category(CourseCategory(id=1, name="新學生一對二"))
  assert is_duo_course_category(CourseCategory(id=2, name="續會學生一對二"))
  assert is_duo_course_category(CourseCategory(id=4, name="自帶學生一對二"))
  assert not is_duo_course_category(CourseCategory(id=3, name="新學生一對一"))
  assert not is_duo_course_category(CourseCategory(id=5, name="Pilates 小班"))
  assert not is_duo_course_category(CourseCategory(id=6, name="Yoga Flow"))


@pytest.mark.parametrize(
  "raw,expected",
  [
    ("91234567", "91234567"),
    ("85291234567", "91234567"),
    ("+85291234567", "91234567"),
    ("bad", None),
  ],
)
def test_hk_local_eight(raw, expected):
  assert _hk_local_eight(raw) == expected


def test_resolve_partner_invalid_phone_raises():
  from unittest.mock import MagicMock

  from app.duo_groups import resolve_partner_student

  db = MagicMock()
  with pytest.raises(HTTPException) as exc:
    resolve_partner_student(db, "123", primary_student_id=1)
  assert exc.value.status_code == 400