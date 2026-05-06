"""Nuclei JSON-Lines parsing — no live binary, just monkeypatched subprocess.run."""

from __future__ import annotations

import subprocess
from datetime import timedelta
from typing import Any

import pytest

from asm.misconfig import nuclei

# Real-shape nuclei -jsonl record. Mirrors the apache-mod-negotiation-listing
# template hit, including the full nested classification block and an Asia/
# Karachi-style timestamp offset (+05:00) of the kind operators in this region see.
NUCLEI_FINDING_FIXTURE: dict[str, Any] = {
    "template": "http/misconfiguration/apache/apache-mod-negotiation-listing.yaml",
    "template-id": "apache-mod-negotiation-listing",
    "template-url": "https://templates.nuclei.sh/public/apache-mod-negotiation-listing",
    "info": {
        "name": "Apache mod_negotiation - Filename Bruteforcing",
        "author": ["geeknik"],
        "tags": ["apache", "misconfig"],
        "description": "Apache module mod_negotiation enumerates filenames on the server.",
        "severity": "low",
        "classification": {
            "cwe-id": ["cwe-200"],
            "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss-score": 5.3,
            "cve-id": None,
            "epss-score": None,
        },
    },
    "type": "http",
    "host": "https://acme.example.com",
    "matched-at": "https://acme.example.com/index",
    "extracted-results": ["index.html.bak", "index.html.old"],
    "ip": "10.0.0.1",
    "timestamp": "2026-05-06T18:12:39.760492+05:00",
    "matcher-status": True,
}


def test_parse_finding_full_shape() -> None:
    f = nuclei._parse_finding(NUCLEI_FINDING_FIXTURE)
    assert f.template_id == "apache-mod-negotiation-listing"
    assert f.name.startswith("Apache mod_negotiation")
    assert f.severity == "low"
    assert f.host == "https://acme.example.com"
    assert f.matched_at == "https://acme.example.com/index"
    assert f.cwe_ids == ["cwe-200"]
    assert f.cvss_score == 5.3
    assert "apache" in f.tags
    assert f.extracted_results == ["index.html.bak", "index.html.old"]


def test_parse_finding_handles_null_classification() -> None:
    """Some templates emit info.classification: null — cwe_ids/cvss_score must default cleanly."""
    raw: dict[str, Any] = {
        **NUCLEI_FINDING_FIXTURE,
        "info": {**NUCLEI_FINDING_FIXTURE["info"], "classification": None},
    }
    f = nuclei._parse_finding(raw)
    assert f.cwe_ids == []
    assert f.cvss_score is None
    # Other fields untouched
    assert f.template_id == "apache-mod-negotiation-listing"
    assert f.severity == "low"


def test_parse_finding_timestamp_preserves_timezone_offset() -> None:
    """Nuclei emits ISO-8601 timestamps with the local offset (e.g. +05:00).
    Don't silently UTC-normalize — operators correlating with logs need the original."""
    f = nuclei._parse_finding(NUCLEI_FINDING_FIXTURE)
    assert f.timestamp.utcoffset() == timedelta(hours=5)
    assert f.timestamp.year == 2026
    assert f.timestamp.month == 5
    assert f.timestamp.day == 6


def test_scan_hosts_raises_when_nuclei_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*a: Any, **kw: Any) -> Any:
        raise FileNotFoundError("nuclei")

    monkeypatch.setattr(subprocess, "run", _raise)
    with pytest.raises(RuntimeError, match="nuclei not on PATH"):
        nuclei.scan_hosts(["acme.example.com"])
