"""[F005][S003]
Feature: Balance Sync & Integrations
Step: (see Logic)
Logic: OTP / SMS hook for verification flows.
"""

from __future__ import annotations

import random
import string
from typing import Protocol

from .logutil import log_event


class SmsOtpProvider(Protocol):
    def send_registration_otp(self, phone: str, code: str) -> None: ...


class MockSmsOtpProvider:
    """Logs OTP; optional fixed code via REGISTER_OTP_MOCK_CODE in env (.env not always loaded — use settings)."""

    def send_registration_otp(self, phone: str, code: str) -> None:
        log_event("sms_otp_mock_send", phone=phone[-4:], code=code)


def generate_otp_code(length: int = 6) -> str:
    return "".join(random.choices(string.digits, k=length))


def get_otp_provider() -> MockSmsOtpProvider:
    return MockSmsOtpProvider()
