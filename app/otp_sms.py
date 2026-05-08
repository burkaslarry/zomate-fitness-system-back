"""Features F006:SmsOtpAdapterSeam -- Protocol + mock; production swaps to Twilio (TODO).

SmsOtpAdapterSeam: ``get_otp_provider()`` returns mock logging registration codes today.
TODO(Twilio): Replace ``MockSmsOtpProvider`` with a ``TwilioSmsOtpProvider`` that calls
the Twilio Verify API (or Programmable SMS) using env ``TWILIO_ACCOUNT_SID``,
``TWILIO_AUTH_TOKEN``, ``TWILIO_MESSAGING_SERVICE_SID`` (or from number). Keep the
``SmsOtpProvider`` protocol so registration tests can still mock sends.
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
