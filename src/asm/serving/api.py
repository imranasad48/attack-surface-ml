"""FastAPI surface. Auth, input validation, audit logging — all enforced here."""
from __future__ import annotations
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from asm.config import get_settings
from asm.serving.audit import audit_log

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: str | None = Depends(api_key_header)) -> str:
    settings = get_settings()
    if not key or key != settings.api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")
    return key


app = FastAPI(title="Attack Surface ML", version="0.1.0")


@app.middleware("http")
async def audit_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
    audit_log(event="request.start", path=request.url.path, method=request.method)
    response = await call_next(request)
    audit_log(event="request.end", path=request.url.path, status=response.status_code)
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


class PredictRequest(BaseModel):
    asset_id: str = Field(min_length=1, max_length=128)
    cve_ids: list[str] = Field(min_length=1, max_length=500)


class PredictResponse(BaseModel):
    asset_id: str
    risk_score: float = Field(ge=0.0, le=1.0)
    model_version: str


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest, _: str = Depends(require_api_key)) -> PredictResponse:
    # TODO: load signed model, score, return.
    return PredictResponse(asset_id=req.asset_id, risk_score=0.0, model_version="0.0.0")
