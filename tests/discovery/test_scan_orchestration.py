"""scan.discover() orchestration — verify per-host failures don't abort the run."""

from __future__ import annotations

from pathlib import Path

import pytest

from asm.discovery import scan
from asm.discovery.schemas import PortInfo


def test_one_host_failure_does_not_abort(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """One subdomain raising RuntimeError is logged and skipped; others still scan."""
    monkeypatch.setattr(scan, "DISCOVERY_DIR", tmp_path)
    monkeypatch.setattr(
        scan,
        "enumerate_subdomains",
        lambda target: ["a.example.com", "b.example.com", "c.example.com"],
    )
    monkeypatch.setattr(scan, "_subfinder_version", lambda: "v2.14.0")
    monkeypatch.setattr(scan, "_nmap_version", lambda: "7.80")

    fake_port = PortInfo(port=80, protocol="tcp", state="open", service="http")

    def fake_scan_host(host: str, ports: str = "") -> list[PortInfo]:
        if host == "b.example.com":
            raise RuntimeError("nmap timed out")
        return [fake_port]

    monkeypatch.setattr(scan, "scan_host", fake_scan_host)

    result = scan.discover("example.com", max_assets=10)

    assert result.subdomains_found == 3
    hostnames = {a.hostname for a in result.assets}
    # The target itself is always scanned; b was skipped after raising
    assert hostnames == {"example.com", "a.example.com", "c.example.com"}
    for asset in result.assets:
        assert len(asset.ports) == 1
        assert asset.ports[0].port == 80


def test_truncation_keeps_max_assets_but_records_original_count(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """When the candidate list (target + subdomains) exceeds max_assets, scan
    only the first N — record the original subfinder count in subdomains_found,
    and put the target itself at position 0 so a real apex is always covered."""
    monkeypatch.setattr(scan, "DISCOVERY_DIR", tmp_path)
    monkeypatch.setattr(
        scan,
        "enumerate_subdomains",
        lambda target: [f"sub{i}.example.com" for i in range(100)],
    )
    monkeypatch.setattr(scan, "_subfinder_version", lambda: "v2.14.0")
    monkeypatch.setattr(scan, "_nmap_version", lambda: "7.80")
    monkeypatch.setattr(scan, "scan_host", lambda host, ports="": [])

    result = scan.discover("example.com", max_assets=5)

    assert result.subdomains_found == 100  # what subfinder found, unaffected by truncation
    assert len(result.assets) == 5  # 101 candidates (target + 100 subs), capped at 5
    assert result.assets[0].hostname == "example.com"  # target scanned first
