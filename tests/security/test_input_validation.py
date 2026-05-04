"""Input validation is a security control. Test it like one."""

from fastapi.testclient import TestClient

from asm.serving.api import app

client = TestClient(app)
HEAD = {"X-API-Key": "test-key"}


def test_rejects_oversized_cve_list() -> None:
    r = client.post(
        "/predict",
        headers=HEAD,
        json={"asset_id": "a1", "cve_ids": [f"CVE-2024-{i:04d}" for i in range(1000)]},
    )
    assert r.status_code == 422


def test_rejects_empty_asset_id() -> None:
    r = client.post("/predict", headers=HEAD, json={"asset_id": "", "cve_ids": ["CVE-2024-0001"]})
    assert r.status_code == 422
