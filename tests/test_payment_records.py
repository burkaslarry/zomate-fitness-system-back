"""[F004][S002] Payment record helpers — HKT timestamps."""

from datetime import datetime

from app.payment_records import payment_created_at_iso


def test_payment_created_at_iso_uses_hkt() -> None:
    """Naive UTC stored in DB should serialize with +08:00 offset."""
    utc = datetime(2026, 7, 17, 6, 43, 50)
    iso = payment_created_at_iso(utc)
    parsed = datetime.fromisoformat(iso)
    assert parsed.hour == 14
    assert parsed.minute == 43
    assert parsed.utcoffset() is not None
    assert parsed.utcoffset().total_seconds() == 8 * 3600
