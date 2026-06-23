"""[F005][S003] Unit tests for WhatsApp Business API helpers."""

from app.whatsapp_business import build_body_parameters, normalize_whatsapp_phone, resolve_meta_template


def test_normalize_whatsapp_phone_hk_local() -> None:
    assert normalize_whatsapp_phone("93103031") == "85293103031"


def test_normalize_whatsapp_phone_hk_with_country_code() -> None:
    assert normalize_whatsapp_phone("+85293103031") == "85293103031"


def test_build_body_parameters_order() -> None:
    params = build_body_parameters(["student_name", "pin"], {"student_name": "Larry", "pin": "10192"})
    assert params == ["Larry", "10192"]


def test_resolve_meta_template_empty_when_unset(monkeypatch) -> None:
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.delenv("WHATSAPP_TEMPLATE_MAP", raising=False)
    assert resolve_meta_template("payment_student_full") is None
