"""Pipeline orchestration — happy path + per-phase failure isolation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from asm.discovery.schemas import Asset, DiscoveryResult, PortInfo
from asm.misconfig.schemas import Finding, MisconfigResult
from asm.orchestrator import pipeline


def _fake_discovery() -> DiscoveryResult:
    asset = Asset(
        hostname="host1.example.com",
        ip="10.0.0.1",
        ports=[
            PortInfo(
                port=80,
                protocol="tcp",
                state="open",
                service="http",
                product="Apache httpd",
                version="2.4.49",
                cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            ),
        ],
    )
    return DiscoveryResult(
        target="example.com",
        scanned_at=datetime.now(UTC),
        subdomains_found=1,
        assets=[asset],
        tool_versions={"subfinder": "v2.14.0", "nmap": "7.80"},
    )


def _fake_misconfig(hosts: list[str]) -> MisconfigResult:
    finding = Finding(
        template_id="apache-mod-negotiation-listing",
        name="Apache mod_negotiation",
        severity="medium",
        host="https://host1.example.com",
        matched_at="https://host1.example.com/index",
        timestamp=datetime.now(UTC),
    )
    return MisconfigResult(
        scanned_at=datetime.now(UTC),
        targets=hosts,
        findings=[finding],
        tool_versions={"nuclei": "v3.8.0"},
    )


def test_run_scan_happy_path_without_api_scoring(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Discovery + misconfig + NVD all succeed; score_via_api=False skips /predict."""
    monkeypatch.setattr(pipeline, "ORCHESTRATOR_DIR", tmp_path)
    monkeypatch.setattr(pipeline, "discover", lambda target, max_assets: _fake_discovery())
    monkeypatch.setattr(pipeline, "scan_misconfig", _fake_misconfig)
    monkeypatch.setattr(
        pipeline,
        "lookup_cves_for_cpes",
        lambda cpes, settings=None: {
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*": [
                "CVE-2021-41773",
                "CVE-2021-42013",
            ]
        },
    )

    result = pipeline.run_scan("example.com", score_via_api=False)

    assert result.status == "completed"
    assert result.target == "example.com"
    assert len(result.assets) == 1

    asset = result.assets[0]
    assert asset.hostname == "host1.example.com"
    assert len(asset.services) == 1
    assert asset.services[0]["cpe"].startswith("cpe:2.3:a:apache")
    cve_ids = sorted({c["cve_id"] for c in asset.cves})
    assert cve_ids == ["CVE-2021-41773", "CVE-2021-42013"]
    # No /predict call → risk_score stays None on every CVE
    assert all(c["risk_score"] is None for c in asset.cves)
    assert asset.risk_summary["n_cves"] == 2
    assert asset.risk_summary["max_risk_score"] is None
    assert asset.risk_summary["n_misconfigs"] == 1
    assert asset.risk_summary["top_misconfig_severity"] == "medium"

    assert result.aggregate_summary["total_assets"] == 1
    assert result.aggregate_summary["total_cves"] == 2
    assert result.aggregate_summary["total_misconfigs"] == 1
    assert result.tool_versions == {
        "subfinder": "v2.14.0",
        "nmap": "7.80",
        "nuclei": "v3.8.0",
    }

    # Result + manifest persisted
    files = list(tmp_path.iterdir())
    assert any(f.name.endswith(".manifest.json") for f in files)
    assert any(
        f.name.endswith(".json") and ".manifest" not in f.name for f in files
    )


def test_discovery_failure_yields_failed_result_without_raising(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A discovery exception must be caught and surfaced as status='failed'."""
    monkeypatch.setattr(pipeline, "ORCHESTRATOR_DIR", tmp_path)

    def boom(target: str, max_assets: int) -> DiscoveryResult:
        raise RuntimeError("subfinder not on PATH")

    monkeypatch.setattr(pipeline, "discover", boom)

    result = pipeline.run_scan("example.com", score_via_api=False)

    assert result.status == "failed"
    assert "discovery failed" in (result.error or "")
    assert result.assets == []


def test_misconfig_failure_does_not_abort_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """nuclei blowing up is tolerable: scan still completes with empty misconfig list."""
    monkeypatch.setattr(pipeline, "ORCHESTRATOR_DIR", tmp_path)
    monkeypatch.setattr(pipeline, "discover", lambda target, max_assets: _fake_discovery())

    def boom(hosts: list[str]) -> MisconfigResult:
        raise RuntimeError("nuclei timed out")

    monkeypatch.setattr(pipeline, "scan_misconfig", boom)
    monkeypatch.setattr(
        pipeline,
        "lookup_cves_for_cpes",
        lambda cpes, settings=None: {
            cpes[0]: ["CVE-2021-41773"],
        },
    )

    result = pipeline.run_scan("example.com", score_via_api=False)

    assert result.status == "completed"
    assert len(result.assets) == 1
    asset = result.assets[0]
    assert asset.misconfigs == []
    assert asset.risk_summary["n_misconfigs"] == 0
    assert asset.risk_summary["top_misconfig_severity"] is None
    # NVD still ran, so CVE data is populated
    assert len(asset.cves) == 1


def test_nvd_failure_continues_with_empty_cves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """NVD outage is tolerable: result completes but error field surfaces the failure."""
    monkeypatch.setattr(pipeline, "ORCHESTRATOR_DIR", tmp_path)
    monkeypatch.setattr(pipeline, "discover", lambda target, max_assets: _fake_discovery())
    monkeypatch.setattr(pipeline, "scan_misconfig", _fake_misconfig)

    def boom(cpes: list[str], settings: Any = None) -> dict[str, list[str]]:
        raise RuntimeError("NVD 503")

    monkeypatch.setattr(pipeline, "lookup_cves_for_cpes", boom)

    result = pipeline.run_scan("example.com", score_via_api=False)

    assert result.status == "completed"
    assert "NVD lookup failed" in (result.error or "")
    asset = result.assets[0]
    assert asset.cves == []
    assert asset.risk_summary["n_cves"] == 0
