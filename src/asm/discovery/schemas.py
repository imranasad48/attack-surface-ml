"""Pydantic schemas for asset-discovery output. TLSInfo is defined for phase 2 — Asset.tls is always None today."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class PortInfo(BaseModel):
    """One open port observed by an nmap -sV scan. Closed/filtered ports are dropped before construction."""

    model_config = ConfigDict(frozen=True)

    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None


class TLSInfo(BaseModel):
    """TLS certificate details. Defined for phase 2 — not populated by the current scan path."""

    model_config = ConfigDict(frozen=True)

    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    san: list[str] = Field(default_factory=list)


class Asset(BaseModel):
    """A single discovered host. tls is always None today; scan results live in ports."""

    model_config = ConfigDict(frozen=True)

    hostname: str
    ip: str | None = None
    ports: list[PortInfo] = Field(default_factory=list)
    tls: TLSInfo | None = None


class DiscoveryResult(BaseModel):
    """Top-level discovery payload. One produced per `discover()` invocation, written to data/discovery/."""

    model_config = ConfigDict(frozen=True)

    target: str
    scanned_at: datetime
    subdomains_found: int
    assets: list[Asset] = Field(default_factory=list)
    tool_versions: dict[str, str] = Field(default_factory=dict)
