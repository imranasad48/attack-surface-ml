from fastapi.testclient import TestClient

from asm.serving.api import app

client = TestClient(app)


def test_health() -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_predict_requires_auth() -> None:
    r = client.post("/predict", json={"asset_id": "a1", "cve_ids": ["CVE-2024-0001"]})
    assert r.status_code == 401


def test_predict_with_key() -> None:
    r = client.post(
        "/predict",
        headers={"X-API-Key": "test-key"},
        json={"asset_id": "a1", "cve_ids": ["CVE-2024-0001"]},
    )
    assert r.status_code == 200
