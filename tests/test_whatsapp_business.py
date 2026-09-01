"""[F005][S003] Unit tests for WhatsApp Business API helpers."""

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from app.whatsapp_business import build_body_parameters, normalize_whatsapp_phone, resolve_meta_template, verify_whatsapp_webhook_signature


def test_normalize_whatsapp_phone_hk_local() -> None:
    assert normalize_whatsapp_phone("93103031") == "85293103031"


def test_normalize_whatsapp_phone_hk_with_country_code() -> None:
    assert normalize_whatsapp_phone("+85293103031") == "85293103031"
    assert normalize_whatsapp_phone("+852 93103031") == "85293103031"


def test_build_body_parameters_order() -> None:
    params = build_body_parameters(["student_name", "pin"], {"student_name": "Larry", "pin": "10192"})
    assert params == ["Larry", "10192"]


def test_resolve_meta_template_empty_when_unset(monkeypatch) -> None:
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.delenv("WHATSAPP_TEMPLATE_MAP", raising=False)
    assert resolve_meta_template("payment_student_full") is None


def test_verify_whatsapp_webhook_signature_valid() -> None:
    secret = "test_app_secret"
    body = b'{"object":"whatsapp_business_account","entry":[]}'
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    assert verify_whatsapp_webhook_signature(body, f"sha256={digest}", secret) is True


def test_verify_whatsapp_webhook_signature_rejects_tampered_body() -> None:
    secret = "test_app_secret"
    body = b'{"object":"whatsapp_business_account","entry":[]}'
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    assert verify_whatsapp_webhook_signature(b'{"object":"evil"}', f"sha256={digest}", secret) is False


def test_verify_whatsapp_webhook_signature_rejects_missing_header() -> None:
    assert verify_whatsapp_webhook_signature(b"{}", None, "secret") is False


def test_whatsapp_webhook_post_requires_signature(monkeypatch) -> None:
    from app import main

    monkeypatch.setattr(main.settings, "whatsapp_app_secret", "test_app_secret")

    client = TestClient(main.app)
    payload = {"object": "whatsapp_business_account", "entry": []}
    response = client.post("/api/webhooks/whatsapp", json=payload)
    assert response.status_code == 403

    body = json.dumps(payload).encode("utf-8")
    digest = hmac.new(b"test_app_secret", body, hashlib.sha256).hexdigest()
    response = client.post(
        "/api/webhooks/whatsapp",
        content=body,
        headers={"Content-Type": "application/json", "X-Hub-Signature-256": f"sha256={digest}"},
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True}
