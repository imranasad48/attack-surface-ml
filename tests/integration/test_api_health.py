from unittest.mock import MagicMock

import numpy as np
from fastapi.testclient import TestClient

from asm.serving import api
from asm.serving.api import app

client = TestClient(app)


def test_health() -> None:
    """Health returns ok plus model state."""
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "model_loaded" in body
    assert "model_version" in body


def test_predict_requires_auth() -> None:
    r = client.post("/predict", json={"asset_id": "a1", "cve_ids": ["CVE-2024-0001"]})
    assert r.status_code == 401


def test_predict_returns_503_when_no_model() -> None:
    """Without a loaded model, /predict returns 503. Defensive design."""
    api._model_state["model"] = None
    r = client.post(
        "/predict",
        headers={"X-API-Key": "test-key"},
        json={"asset_id": "a1", "cve_ids": ["CVE-2024-0001"]},
    )
    assert r.status_code == 503


def test_predict_with_mocked_model() -> None:
    """With a mocked model, /predict returns scored CVEs."""
    mock_model = MagicMock()
    mock_model.predict_proba.return_value = np.array([[0.3, 0.7]])
    api._model_state["model"] = mock_model
    api._model_state["version"] = "test"

    r = client.post(
        "/predict",
        headers={"X-API-Key": "test-key"},
        json={"asset_id": "a1", "cve_ids": ["CVE-2024-0001"]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["asset_id"] == "a1"
    assert body["model_version"] == "test"
    assert len(body["scores"]) == 1
    assert body["scores"][0]["cve_id"] == "CVE-2024-0001"
    assert 0.0 <= body["scores"][0]["risk_score"] <= 1.0

    # cleanup so other tests don't inherit state
    api._model_state["model"] = None
    api._model_state["version"] = "unloaded"
