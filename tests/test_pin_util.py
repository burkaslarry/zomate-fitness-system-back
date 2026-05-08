from app.pin_util import hash_pin, verify_student_pin


def test_hash_and_verify_roundtrip() -> None:
    h = hash_pin("4242")
    assert verify_student_pin("4242", pin_hash=h, legacy_plain=None)


def test_legacy_plain_fallback() -> None:
    assert verify_student_pin("1234", pin_hash=None, legacy_plain="1234")
