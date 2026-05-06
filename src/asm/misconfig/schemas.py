"""Pydantic schemas for misconfiguration scan output. Mirrors discovery/schemas.py — frozen, immutable once produced."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    """One nuclei template hit. Maps a single line of nuclei -jsonl output to a typed record."""

    model_config = ConfigDict(frozen=True)

    template_id: str
    name: str
    severity: Severity
    host: str
    matched_at: str
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    extracted_results: list[str] = Field(default_factory=list)
    timestamp: datetime


class MisconfigResult(BaseModel):
    """Top-level misconfiguration scan payload. One produced per `scan()` invocation, written to data/misconfig/."""

    model_config = ConfigDict(frozen=True)

    scanned_at: datetime
    targets: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    tool_versions: dict[str, str] = Field(default_factory=dict)
