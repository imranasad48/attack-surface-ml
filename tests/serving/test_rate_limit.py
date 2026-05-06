"""Per-API-key rate limit tests for /predict. Closes threat-model.md §5.2."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import numpy as np
import pytest
from fastapi.testclient import TestClient

from asm.serving import api
from asm.serving.api import RATE_LIMIT_PER_MINUTE, app, require_api_key


class _FakeModel:
    """Drop-in for the trained XGBoost — predict_proba returns 0.5 for every row."""

    def predict_proba(self, X: Any) -> np.ndarray:  # noqa: N803  # XGBoost convention
        return np.tile([0.5, 0.5], (len(X), 1))


@pytest.fixture
def authed_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """TestClient with require_api_key bypassed and a fake model loaded.

    Auth is overridden so each test can send its own X-API-Key value without
    having to thread that key through the settings cache. The fake model
    avoids needing MLflow running in tests.
    """
    monkeypatch.setitem(api._model_state, "model", _FakeModel())
    monkeypatch.setitem(api._model_state, "version", "test")
    app.dependency_overrides[require_api_key] = lambda: "ok"
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(require_api_key, None)


def _payload() -> dict[str, Any]:
    return {"asset_id": "asset-1", "cve_ids": ["CVE-2023-12345"]}


def _fresh_key() -> str:
    """A unique X-API-Key per test isolates the per-key bucket from other runs."""
    return f"rl-test-{uuid.uuid4()}"


def test_under_limit_all_succeed(authed_client: TestClient) -> None:
    """60 requests in a fresh bucket all return 200."""
    headers = {"X-API-Key": _fresh_key()}
    for i in range(RATE_LIMIT_PER_MINUTE):
        r = authed_client.post("/predict", json=_payload(), headers=headers)
        assert r.status_code == 200, f"request {i + 1} failed: {r.status_code} {r.text}"


def test_over_limit_returns_429(authed_client: TestClient) -> None:
    """The 61st request in a fresh bucket is rejected with 429."""
    headers = {"X-API-Key": _fresh_key()}
    for i in range(RATE_LIMIT_PER_MINUTE):
        r = authed_client.post("/predict", json=_payload(), headers=headers)
        assert r.status_code == 200, f"request {i + 1} failed before limit: {r.status_code}"
    r = authed_client.post("/predict", json=_payload(), headers=headers)
    assert r.status_code == 429, f"expected 429 on request 61, got {r.status_code}: {r.text}"
