"""Pydantic schemas for the unified orchestrator. Frozen — immutable once produced."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

JobStatus = Literal["pending", "running", "completed", "failed"]


class AssetRiskReport(BaseModel):
    """One discovered host annotated with CVE risk + misconfiguration findings."""

    model_config = ConfigDict(frozen=True)

    hostname: str
    ip: str | None = None
    services: list[dict[str, Any]] = Field(default_factory=list)
    cves: list[dict[str, Any]] = Field(default_factory=list)
    misconfigs: list[dict[str, Any]] = Field(default_factory=list)
    risk_summary: dict[str, Any] = Field(default_factory=dict)


class UnifiedScanResult(BaseModel):
    """End-to-end orchestrator output. One produced per `run_scan()` invocation."""

    model_config = ConfigDict(frozen=True)

    target: str
    scanned_at: datetime
    status: JobStatus
    assets: list[AssetRiskReport] = Field(default_factory=list)
    aggregate_summary: dict[str, Any] = Field(default_factory=dict)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    error: str | None = None


class ScanJob(BaseModel):
    """A single asynchronous scan job tracked by the in-memory job store."""

    model_config = ConfigDict(frozen=True)

    job_id: str
    target: str
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    result: UnifiedScanResult | None = None
    error: str | None = None
