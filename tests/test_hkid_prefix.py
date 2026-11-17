"""[F001][S001] New-student HKID input is a 4-char prefix (e.g. A123), never the full number."""

from datetime import date

import pytest
from pydantic import ValidationError

from app.schemas import MemberCreate, ParqQuestionsIn, StudentRegisterV1


def _base() -> dict:
    return {
        "chinese_name": "陳大文",
        "full_name": "Chan Tai Man",
        "gender": "male",
        "phone": "+85291110004",
        "date_of_birth": date(2000, 1, 1),
        "emergency_contact_name": "Chan Siu Ming",
        "emergency_contact_relationship": "Parent",
        "emergency_contact_phone": "+85291110005",
        "parq": ParqQuestionsIn(),
        "whatsapp_reminder_opt_in": True,
    }


def test_member_create_accepts_and_normalizes_prefix():
    payload = MemberCreate(hkid="ab12", **_base())
    assert payload.hkid == "AB12"


def test_member_create_rejects_full_hkid():
    with pytest.raises(ValidationError):
        MemberCreate(hkid="Z732423(6)", **_base())


def test_student_register_rejects_full_hkid():
    with pytest.raises(ValidationError):
        StudentRegisterV1(
            full_name="Chan Tai Man",
            hkid="Z732423(6)",
            phone="+85291110004",
            date_of_birth=date(2000, 1, 1),
            emergency_contact_name="Chan Siu Ming",
            emergency_contact_phone="+85291110005",
            form_type="new",
            parq=ParqQuestionsIn(),
            package_sessions=10,
            whatsapp_reminder_opt_in=True,
        )
