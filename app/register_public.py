"""[F001][S001]
Feature: Student Onboarding
Step: (see Logic)
Logic: Public registration router split from main.
"""

from __future__ import annotations

import os
import re
import time
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from .database import get_db
from .models import Student
from .otp_sms import generate_otp_code, get_otp_provider
from .pin_util import hash_pin
from .logutil import log_event

router = APIRouter(prefix="/api/register", tags=["register"])

_OTP_TTL = 600.0
_VERIFIED_TTL = 900.0

_otp_store: dict[str, tuple[str, float]] = {}
_verified_phones: dict[str, float] = {}


def _normalize_phone(raw: str) -> str:
    s = re.sub(r"\s+", "", (raw or "").strip())
    if len(s) < 8:
        raise HTTPException(status_code=400, detail="Invalid phone number.")
    return s


class OtpRequestBody(BaseModel):
    phone: str


class OtpVerifyBody(BaseModel):
    phone: str
    code: str = Field(min_length=4, max_length=10)


class ProfileBody(BaseModel):
    phone: str
    legal_name: str = Field(min_length=1, max_length=120)
    hkid_prefix4: str

    @field_validator("hkid_prefix4")
    @classmethod
    def hkid_prefix(cls, v: str) -> str:
        t = "".join((v or "").split()).upper()
        if not re.fullmatch(r"[A-Z0-9]{4}", t):
            raise ValueError("hkid_prefix4 must be exactly 4 alphanumeric characters")
        return t


class PinBody(BaseModel):
    phone: str
    pin: str = Field(min_length=4, max_length=12)


def _mock_code() -> str | None:
    fixed = os.environ.get("REGISTER_OTP_MOCK_CODE", "").strip()
    return fixed or None


@router.post("/otp/request")
def register_otp_request(body: OtpRequestBody, db: Session = Depends(get_db)) -> dict:
    phone = _normalize_phone(body.phone)
    # [F001][S001] Block registration OTP if phone already exists on zomate_fs_students.
    existing = db.query(Student).filter(Student.phone == phone).first()
    if existing is not None:
        log_event("register_otp_blocked_duplicate_phone", phone_suffix=phone[-4:])
        raise HTTPException(status_code=409, detail="Phone already registered.")

    code = _mock_code() or generate_otp_code()
    _otp_store[phone] = (code, time.monotonic() + _OTP_TTL)
    get_otp_provider().send_registration_otp(phone, code)
    log_event("register_otp_requested", phone_suffix=phone[-4:])
    return {"message": "OTP sent (mock in dev).", "expires_in_seconds": int(_OTP_TTL)}


@router.post("/otp/verify")
def register_otp_verify(body: OtpVerifyBody) -> dict:
    phone = _normalize_phone(body.phone)
    entry = _otp_store.get(phone)
    if not entry:
        raise HTTPException(status_code=400, detail="No OTP request for this phone.")
    code, exp = entry
    if time.monotonic() > exp:
        del _otp_store[phone]
        raise HTTPException(status_code=400, detail="OTP expired.")
    if body.code.strip() != code:
        raise HTTPException(status_code=400, detail="Invalid OTP.")

    del _otp_store[phone]
    _verified_phones[phone] = time.monotonic() + _VERIFIED_TTL
    log_event("register_otp_verified", phone_suffix=phone[-4:])
    return {"message": "Verified.", "verified": True}


def _require_verified(phone: str) -> None:
    phone = _normalize_phone(phone)
    exp = _verified_phones.get(phone)
    if not exp or time.monotonic() > exp:
        raise HTTPException(status_code=401, detail="Complete OTP verification first.")
    _verified_phones[phone] = time.monotonic() + _VERIFIED_TTL


@router.post("/profile")
def register_profile(body: ProfileBody, db: Session = Depends(get_db)) -> dict:
    _require_verified(body.phone)
    phone = _normalize_phone(body.phone)

    student = db.query(Student).filter(Student.phone == phone).first()
    if student is None:
        student = Student(
            full_name=body.legal_name.strip(),
            phone=phone,
            hkid_prefix4=body.hkid_prefix4,
            coach_trial_quota_remaining=1,
            disclaimer_accepted=False,
        )
        db.add(student)
    else:
        student.full_name = body.legal_name.strip()
        student.hkid_prefix4 = body.hkid_prefix4

    db.commit()
    db.refresh(student)
    log_event("register_profile_saved", student_id=student.id)
    return {"message": "Profile saved.", "student_id": student.id}


@router.post("/pin")
def register_pin(body: PinBody, db: Session = Depends(get_db)) -> dict:
    _require_verified(body.phone)
    phone = _normalize_phone(body.phone)
    student = db.query(Student).filter(Student.phone == phone).first()
    if not student:
        raise HTTPException(status_code=404, detail="Student not found; save profile first.")
    if student.pin_hash:
        raise HTTPException(status_code=409, detail="PIN already set.")

    student.pin_hash = hash_pin(body.pin)
    db.add(student)
    db.commit()
    db.refresh(student)

    _verified_phones.pop(phone, None)
    log_event("register_pin_set", student_id=student.id)
    return {"message": "PIN saved.", "student_id": student.id}
