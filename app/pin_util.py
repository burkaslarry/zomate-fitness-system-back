"""PIN hashing (bcrypt) with legacy plain-text fallback."""

from __future__ import annotations

import bcrypt


def hash_pin(pin: str) -> str:
    return bcrypt.hashpw(pin.strip().encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_student_pin(pin: str, *, pin_hash: str | None, legacy_plain: str | None) -> bool:
    raw = pin.strip()
    if pin_hash:
        try:
            return bcrypt.checkpw(raw.encode("utf-8"), pin_hash.encode("ascii"))
        except ValueError:
            return False
    if legacy_plain is not None:
        return legacy_plain.strip() == raw
    return False
