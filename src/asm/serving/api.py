"""FastAPI surface. Auth, input validation, audit logging, real model predictions."""

from __future__ import annotations

import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import mlflow
import mlflow.xgboost
import numpy as np
import pandas as pd
import structlog
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from asm.config import get_settings
from asm.serving.audit import audit_log

log = structlog.get_logger()

MODEL_NAME = "cve-risk-classifier"
MODEL_STAGE = "1"  # version 1; promote to "Production" alias when stable
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

# Loaded once at startup, reused. XGBoost predict is thread-safe.
_model_state: dict[str, Any] = {"model": None, "version": "unloaded"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model at startup. If load fails, server starts but /predict returns 503."""
    settings = get_settings()
    mlflow.set_tracking_uri(settings.mlflow_tracking_uri)
    try:
        uri = f"models:/{MODEL_NAME}/{MODEL_STAGE}"
        log.info("model.load.start", uri=uri)
        _model_state["model"] = mlflow.xgboost.load_model(uri)
        _model_state["version"] = MODEL_STAGE
        log.info("model.load.ok", uri=uri)
    except Exception as e:
        log.error("model.load.fail", error=str(e))
    yield
    log.info("server.shutdown")


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: str | None = Depends(api_key_header)) -> str:
    settings = get_settings()
    if not key or key != settings.api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")
    return key


app = FastAPI(title="Attack Surface ML", version="0.1.0", lifespan=lifespan)


@app.middleware("http")
async def audit_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
    audit_log(event="request.start", path=request.url.path, method=request.method)
    response = await call_next(request)
    audit_log(event="request.end", path=request.url.path, status=response.status_code)
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "model_loaded": str(_model_state["model"] is not None),
        "model_version": _model_state["version"],
    }


class PredictRequest(BaseModel):
    asset_id: str = Field(min_length=1, max_length=128)
    cve_ids: list[str] = Field(min_length=1, max_length=500)


class CVEScore(BaseModel):
    cve_id: str
    risk_score: float = Field(ge=0.0, le=1.0)
    high_risk: bool


class PredictResponse(BaseModel):
    asset_id: str
    model_version: str
    max_risk_score: float
    scores: list[CVEScore]


def _build_features(cve_ids: list[str]) -> pd.DataFrame:
    """Mirror of training-time feature engineering. Must stay in sync with train.py."""
    rows = []
    for cve in cve_ids:
        if not CVE_RE.match(cve):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Invalid CVE ID format: {cve}",
            )
        year = int(cve.split("-")[1])
        seq = int(cve.split("-")[2])
        rows.append(
            {
                "cve_year": year,
                "cve_age_years": datetime.now(UTC).year - year,
                "cve_seq_log": float(np.log1p(seq)),
            }
        )
    return pd.DataFrame(rows)


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest, _: str = Depends(require_api_key)) -> PredictResponse:
    model = _model_state["model"]
    if model is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Model not loaded")

    features = _build_features(req.cve_ids)
    proba_arr = model.predict_proba(features)[:, 1]

    scores = [
        CVEScore(cve_id=cve, risk_score=float(p), high_risk=bool(p >= 0.5))
        for cve, p in zip(req.cve_ids, proba_arr, strict=True)
    ]
    audit_log(
        event="predict",
        asset_id=req.asset_id,
        n_cves=len(req.cve_ids),
        max_score=float(proba_arr.max()),
        model_version=_model_state["version"],
    )
    return PredictResponse(
        asset_id=req.asset_id,
        model_version=str(_model_state["version"]),
        max_risk_score=float(proba_arr.max()),
        scores=scores,
    )
