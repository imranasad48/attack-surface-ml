"""End-to-end scan pipeline: target → discovery → misconfig → NVD lookup → /predict scoring → unified report."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import structlog

from asm.config import get_settings
from asm.discovery.scan import discover
from asm.discovery.schemas import DiscoveryResult
from asm.misconfig.scan import scan as scan_misconfig
from asm.misconfig.schemas import Finding, MisconfigResult
from asm.orchestrator.nvd import lookup_cves_for_cpes
from asm.orchestrator.schemas import AssetRiskReport, UnifiedScanResult

log = structlog.get_logger()

ORCHESTRATOR_DIR = Path("data/orchestrator")
PREDICT_URL = "http://127.0.0.1:8000/predict"
PREDICT_TIMEOUT = 30
PREDICT_CHUNK_SIZE = 500  # matches PredictRequest.cve_ids max_length in serving/api.py

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_target(target: str) -> str:
    return target.replace("/", "_").replace(":", "_")


def _result_path(target: str, scanned_at: datetime) -> Path:
    ts = scanned_at.strftime("%Y%m%dT%H%M%SZ")
    return ORCHESTRATOR_DIR / f"{_safe_target(target)}-{ts}.json"


def _write_result(result: UnifiedScanResult) -> Path:
    """Serialize the UnifiedScanResult to JSON, named by target + UTC timestamp."""
    ORCHESTRATOR_DIR.mkdir(parents=True, exist_ok=True)
    out = _result_path(result.target, result.scanned_at)
    out.write_text(result.model_dump_json(indent=2))
    return out


def _write_manifest(result_path: Path, target: str, status: str) -> Path:
    """Write a sibling .manifest.json with sha256 + provenance, mirroring discovery/misconfig."""
    payload = result_path.read_bytes()
    digest = _sha256(payload)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    manifest = {
        "file": result_path.name,
        "sha256": digest,
        "ts": ts,
        "bytes": len(payload),
        "target": target,
        "status": status,
    }
    manifest_path = result_path.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    log.info("orchestrator.manifest.written", **manifest)
    return manifest_path


def _persist(result: UnifiedScanResult) -> Path:
    result_path = _write_result(result)
    _write_manifest(result_path, result.target, result.status)
    return result_path


def _index_findings_by_host(misconfig: MisconfigResult) -> dict[str, list[Finding]]:
    """Index nuclei findings by host. nuclei reports the host as a URL; match suffix on hostname."""
    by_host: dict[str, list[Finding]] = {}
    for f in misconfig.findings:
        by_host.setdefault(f.host, []).append(f)
    return by_host


def _findings_for_hostname(hostname: str, by_host: dict[str, list[Finding]]) -> list[Finding]:
    """Match a discovery hostname to nuclei host strings (which are usually full URLs)."""
    out: list[Finding] = []
    for host, findings in by_host.items():
        if hostname in host:
            out.extend(findings)
    return out


def _services_from_asset(asset: Any) -> list[dict[str, Any]]:
    return [
        {
            "port": p.port,
            "service": p.service,
            "product": p.product,
            "version": p.version,
            "cpe": p.cpe,
        }
        for p in asset.ports
    ]


def _cves_for_asset(asset: Any, cpe_to_cves: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Build the per-asset CVE records. Same CVE may appear twice if reached via two CPEs."""
    out: list[dict[str, Any]] = []
    for port in asset.ports:
        if not port.cpe:
            continue
        for cve_id in cpe_to_cves.get(port.cpe, []):
            out.append(
                {
                    "cve_id": cve_id,
                    "cpe_source": port.cpe,
                    "risk_score": None,
                    "high_risk": False,
                }
            )
    return out


def _score_asset_cves(asset_hostname: str, cves: list[dict[str, Any]], api_key: str) -> list[dict[str, Any]]:
    """POST /predict in chunks of PREDICT_CHUNK_SIZE; merge risk_score back into cves.

    On any HTTP failure, leave risk_score=None and return — the caller logs and continues.
    """
    if not cves:
        return cves

    unique_cve_ids = list(dict.fromkeys(c["cve_id"] for c in cves))
    score_by_cve: dict[str, tuple[float, bool]] = {}

    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    with httpx.Client(timeout=PREDICT_TIMEOUT) as client:
        for i in range(0, len(unique_cve_ids), PREDICT_CHUNK_SIZE):
            chunk = unique_cve_ids[i : i + PREDICT_CHUNK_SIZE]
            response = client.post(
                PREDICT_URL,
                headers=headers,
                json={"asset_id": asset_hostname, "cve_ids": chunk},
            )
            response.raise_for_status()
            payload = response.json()
            for s in payload.get("scores", []):
                score_by_cve[s["cve_id"]] = (
                    float(s["risk_score"]),
                    bool(s["high_risk"]),
                )

    enriched: list[dict[str, Any]] = []
    for c in cves:
        score = score_by_cve.get(c["cve_id"])
        if score is None:
            enriched.append(c)
        else:
            enriched.append({**c, "risk_score": score[0], "high_risk": score[1]})
    return enriched


def _risk_summary(cves: list[dict[str, Any]], misconfigs: list[dict[str, Any]]) -> dict[str, Any]:
    unique_ids = {c["cve_id"] for c in cves}
    high_risk_ids = {c["cve_id"] for c in cves if c.get("high_risk")}
    scored = [c["risk_score"] for c in cves if c.get("risk_score") is not None]
    max_score = max(scored) if scored else None
    top_sev: str | None = None
    for m in misconfigs:
        sev = m.get("severity")
        if sev is None:
            continue
        if top_sev is None or _SEVERITY_ORDER.get(sev, -1) > _SEVERITY_ORDER.get(top_sev, -1):
            top_sev = sev
    return {
        "n_cves": len(unique_ids),
        "n_high_risk_cves": len(high_risk_ids),
        "max_risk_score": max_score,
        "n_misconfigs": len(misconfigs),
        "top_misconfig_severity": top_sev,
    }


def _aggregate_summary(assets: list[AssetRiskReport], duration_s: float) -> dict[str, Any]:
    total_cves = sum(a.risk_summary.get("n_cves", 0) for a in assets)
    total_misconfigs = sum(a.risk_summary.get("n_misconfigs", 0) for a in assets)
    per_asset_max = [a.risk_summary["max_risk_score"] for a in assets if a.risk_summary.get("max_risk_score") is not None]
    return {
        "total_assets": len(assets),
        "total_cves": total_cves,
        "total_misconfigs": total_misconfigs,
        "max_risk_across_assets": max(per_asset_max) if per_asset_max else None,
        "scan_duration_seconds": round(duration_s, 3),
    }


def _failed_result(target: str, scanned_at: datetime, err: str) -> UnifiedScanResult:
    """Build a status='failed' result, persist it, and return it."""
    result = UnifiedScanResult(
        target=target,
        scanned_at=scanned_at,
        status="failed",
        assets=[],
        aggregate_summary={},
        tool_versions={},
        error=err,
    )
    _persist(result)
    return result


def run_scan(target: str, max_assets: int = 10, score_via_api: bool = True) -> UnifiedScanResult:
    """Run the full pipeline. Lower max_assets default than discovery — NVD lookups are slow."""
    started = time.monotonic()
    scanned_at = datetime.now(UTC)
    settings = get_settings()

    # Phase 1 — Discovery
    try:
        discovery_result: DiscoveryResult = discover(target, max_assets=max_assets)
        log.info(
            "pipeline.discovery.done",
            target=target,
            n_assets=len(discovery_result.assets),
        )
    except Exception as e:
        log.error("pipeline.discovery.error", target=target, error=str(e))
        return _failed_result(target, scanned_at, f"discovery failed: {e}")

    # Phase 2 — Misconfig (failure here does NOT abort the scan)
    hosts = [a.hostname for a in discovery_result.assets]
    misconfig_result: MisconfigResult
    try:
        misconfig_result = scan_misconfig(hosts)
        log.info("pipeline.misconfig.done", n_findings=len(misconfig_result.findings))
    except Exception as e:
        log.error("pipeline.misconfig.error", error=str(e))
        misconfig_result = MisconfigResult(scanned_at=scanned_at, targets=hosts, findings=[], tool_versions={})

    findings_by_host = _index_findings_by_host(misconfig_result)

    # Phase 3 — CPE → CVE lookup
    unique_cpes: list[str] = []
    seen_cpes: set[str] = set()
    for asset in discovery_result.assets:
        for port in asset.ports:
            if port.cpe and port.cpe not in seen_cpes:
                seen_cpes.add(port.cpe)
                unique_cpes.append(port.cpe)

    nvd_error: str | None = None
    cpe_to_cves: dict[str, list[str]] = {}
    if unique_cpes:
        try:
            cpe_to_cves = lookup_cves_for_cpes(unique_cpes, settings=settings)
            total_cves = sum(len(v) for v in cpe_to_cves.values())
            log.info(
                "pipeline.nvd.done",
                unique_cpes=len(unique_cpes),
                total_cves=total_cves,
            )
        except Exception as e:
            log.error("pipeline.nvd.error", error=str(e))
            nvd_error = f"NVD lookup failed: {e}"
            cpe_to_cves = {}

    # Phase 4 — Per-asset CVE scoring via local /predict
    assets: list[AssetRiskReport] = []
    for asset in discovery_result.assets:
        services = _services_from_asset(asset)
        cves = _cves_for_asset(asset, cpe_to_cves)

        if score_via_api and cves:
            try:
                cves = _score_asset_cves(asset.hostname, cves, settings.api_key)
            except Exception as e:
                log.error("pipeline.scoring.error", host=asset.hostname, error=str(e))

        misconfigs_for_host = [f.model_dump(mode="json") for f in _findings_for_hostname(asset.hostname, findings_by_host)]
        report = AssetRiskReport(
            hostname=asset.hostname,
            ip=asset.ip,
            services=services,
            cves=cves,
            misconfigs=misconfigs_for_host,
            risk_summary=_risk_summary(cves, misconfigs_for_host),
        )
        assets.append(report)

    duration = time.monotonic() - started
    tool_versions = {
        **discovery_result.tool_versions,
        **misconfig_result.tool_versions,
    }
    result = UnifiedScanResult(
        target=target,
        scanned_at=scanned_at,
        status="completed",
        assets=assets,
        aggregate_summary=_aggregate_summary(assets, duration),
        tool_versions=tool_versions,
        error=nvd_error,  # surfaced even on a "completed" scan if NVD partially failed
    )
    _persist(result)
    log.info(
        "pipeline.complete",
        target=target,
        duration=round(duration, 3),
        n_assets=len(assets),
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified ASM scan: discovery + misconfig + CVE scoring.")
    parser.add_argument("target", help="Apex domain to scan (e.g. example.com)")
    parser.add_argument(
        "--max-assets",
        type=int,
        default=10,
        help="Cap on hosts scanned end-to-end (default 10)",
    )
    parser.add_argument(
        "--no-score",
        action="store_true",
        help="Skip the /predict scoring phase (useful when the API isn't running)",
    )
    args = parser.parse_args()
    result = run_scan(args.target, max_assets=args.max_assets, score_via_api=not args.no_score)
    print(_result_path(result.target, result.scanned_at))


if __name__ == "__main__":
    main()
