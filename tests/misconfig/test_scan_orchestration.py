"""scan.scan() orchestration — empty-host short-circuit + finding aggregation/manifest write."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from asm.misconfig import scan
from asm.misconfig.schemas import Finding


def test_scan_empty_hosts_short_circuits_without_invoking_nuclei(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Empty host list returns immediately — nuclei must not be invoked, no files written."""
    called = False

    def fake_scan_hosts(*a: Any, **kw: Any) -> list[Finding]:
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(scan, "MISCONFIG_DIR", tmp_path)
    monkeypatch.setattr(scan, "scan_hosts", fake_scan_hosts)

    result = scan.scan([])

    assert called is False
    assert result.targets == []
    assert result.findings == []
    assert result.tool_versions == {}
    assert list(tmp_path.iterdir()) == []  # nothing written


def test_scan_aggregates_findings_and_writes_manifest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Non-empty scan: findings flow through, tool_versions populated, both files land in MISCONFIG_DIR."""
    fake_finding = Finding(
        template_id="apache-mod-negotiation-listing",
        name="Apache mod_negotiation - Filename Bruteforcing",
        severity="low",
        host="https://host1.example.com",
        matched_at="https://host1.example.com/index",
        timestamp=datetime(2026, 5, 6, 18, 12, 39, tzinfo=UTC),
        tags=["apache", "misconfig"],
        cwe_ids=["cwe-200"],
        cvss_score=5.3,
    )
    monkeypatch.setattr(scan, "MISCONFIG_DIR", tmp_path)
    monkeypatch.setattr(scan, "scan_hosts", lambda hosts, **kw: [fake_finding])
    monkeypatch.setattr(scan, "_nuclei_version", lambda: "v3.8.0")

    result = scan.scan(["host1.example.com", "host2.example.com"])

    assert result.targets == ["host1.example.com", "host2.example.com"]
    assert len(result.findings) == 1
    assert result.findings[0].template_id == "apache-mod-negotiation-listing"
    assert result.tool_versions == {"nuclei": "v3.8.0"}

    files = list(tmp_path.iterdir())
    result_files = [f for f in files if f.name.endswith(".json") and ".manifest" not in f.name]
    manifest_files = [f for f in files if f.name.endswith(".manifest.json")]
    assert len(result_files) == 1
    assert len(manifest_files) == 1
    assert result_files[0].name.startswith("misconfig-")

    manifest = json.loads(manifest_files[0].read_text())
    assert manifest["n_targets"] == 2
    assert manifest["file"] == result_files[0].name
    assert len(manifest["sha256"]) == 64  # SHA-256 hex digest
    assert manifest["bytes"] > 0
