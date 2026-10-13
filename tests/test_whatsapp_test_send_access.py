"""[F005][S003] Verify live test-send access and outgoing positional parameters."""

import json
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main, whatsapp_business


@pytest.mark.parametrize(
    ("username", "role", "expected"),
    [("masterzoe", "ADMIN", 200), ("masterzoe", "MASTER_ADMIN", 200),
     ("masterfung", "MASTER_ADMIN", 403), ("another_admin", "ADMIN", 403),
     ("masterzoe", "CLERK", 403), ("coach", "COACH", 403)],
)
def test_live_test_send_is_masterzoe_only(monkeypatch, username, role, expected):
    """[F005][S003] Reject other roles/accounts before the provider can send."""
    sends = []

    def current_user():
        """[F005][S003] Supply an authenticated test identity without a database."""
        return SimpleNamespace(username=username, role=role)

    def send_template(phone, template_name, **kwargs):
        """[F005][S003] Record the provider call without transmitting a message."""
        sends.append((phone, template_name, kwargs))
        return whatsapp_business.WhatsAppSendResult(
            ok=True, dry_run=False, message_id="wamid.test", to=phone, template_name=template_name,
        )

    monkeypatch.setattr(main, "get_whatsapp_client", lambda: SimpleNamespace(send_template=send_template))
    main.app.dependency_overrides[main.get_current_user] = current_user
    try:
        response = TestClient(main.app).post("/api/admin/whatsapp/test-send", json={
            "phone": "93103031", "template_name": "zomate_payment_pending",
            "language_code": "zh_HK", "body_parameters": ["Example"],
        })
        assert response.status_code == expected
        assert len(sends) == (1 if expected == 200 else 0)
    finally:
        main.app.dependency_overrides.pop(main.get_current_user, None)


def test_live_test_send_requires_authentication():
    """[F005][S003] Anonymous callers cannot invoke test sends."""
    response = TestClient(main.app).post("/api/admin/whatsapp/test-send", json={
        "phone": "93103031", "template_name": "zomate_payment_pending",
    })
    assert response.status_code == 401


def test_meta_send_keeps_variable_order_and_flattens_installment_notes(monkeypatch):
    """[F005][S003] Exercise the real HTTP payload path against a mock transport."""
    captured = []
    real_client = httpx.Client

    def handler(request):
        """[F005][S003] Capture the Meta request without contacting the service."""
        captured.append(request)
        return httpx.Response(200, json={"messages": [{"id": "wamid.test"}]})

    def transport_client(**kwargs):
        """[F005][S003] Preserve the client interface while substituting transport."""
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(whatsapp_business.settings, "whatsapp_enabled", True)
    monkeypatch.setattr(whatsapp_business.settings, "whatsapp_phone_number_id", "1292795760587834")
    monkeypatch.setattr(whatsapp_business.settings, "whatsapp_access_token", "test-token")
    monkeypatch.setattr(whatsapp_business.httpx, "Client", transport_client)
    result = whatsapp_business.WhatsAppBusinessClient().send_template(
        "93103031", "zomate_payment_installment", language_code="zh_HK",
        body_parameters=["Larry Lo", "第5堂付第2期\n第9堂付第3期", ""],
    )
    assert result.ok and not result.dry_run and result.message_id == "wamid.test"
    request = captured[0]
    assert request.url.path.endswith("/1292795760587834/messages")
    assert request.headers["Authorization"] == "Bearer test-token"
    payload = json.loads(request.content)
    assert payload["to"] == "85293103031"
    assert payload["template"]["language"] == {"code": "zh_HK"}
    assert payload["template"]["components"][0]["parameters"] == [
        {"type": "text", "text": "Larry Lo"},
        {"type": "text", "text": "第5堂付第2期 第9堂付第3期"},
        {"type": "text", "text": "—"},
    ]
