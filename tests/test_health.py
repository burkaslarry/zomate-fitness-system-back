from fastapi.testclient import TestClient

from app.health_app import liveness_payload
from app.main import app


def test_liveness_payload_shape() -> None:
    p = liveness_payload("test-id")
    assert p["status"] == "ok"
    assert "ts" in p and "uptime_seconds" in p
    assert p["instance_id"] == "test-id"


def test_api_health_endpoint() -> None:
    client = TestClient(app)
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "uptime_seconds" in body
    assert "instance_id" in body
