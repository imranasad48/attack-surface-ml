"""Skeleton for ART-based robustness tests. Fill in once a model exists."""

import pytest


@pytest.mark.skip(reason="Wire up after baseline model is registered in MLflow")
def test_robust_to_zoo_attack() -> None:
    # 1. load registered model
    # 2. craft ZOO/HopSkipJump perturbations on a clean test set
    # 3. assert robust accuracy >= threshold
    raise NotImplementedError
