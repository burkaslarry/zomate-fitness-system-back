"""[F001][S005]
Feature: Student Onboarding
Step: (see Logic)
Logic: Unit tests for registration helpers.
"""

import pytest
from pydantic import ValidationError

from app.register_public import ProfileBody


def test_profile_hkid_prefix_validation() -> None:
    p = ProfileBody(phone="91234567", legal_name="Test User", hkid_prefix4="A123")
    assert p.hkid_prefix4 == "A123"


def test_profile_hkid_prefix_invalid() -> None:
    with pytest.raises(ValidationError):
        ProfileBody(phone="91234567", legal_name="Test User", hkid_prefix4="BAD")
