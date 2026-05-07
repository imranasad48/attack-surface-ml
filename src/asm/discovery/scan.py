"""Orchestrate asset discovery. Enumerate subdomains, then nmap each, write a hash-validated DiscoveryResult."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import structlog

from asm.discovery.nmap import _nmap_version, scan_host
from asm.discovery.schemas import Asset, DiscoveryResult
from asm.discovery.subfinder import _subfinder_version, enumerate_subdomains

log = structlog.get_logger()

DISCOVERY_DIR = Path("data/discovery")
DEFAULT_MAX_ASSETS = 50  # 50 hosts x ~1 min/host bounds a demo scan; tune up for full inventories

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_target(target: str) -> str:
    """Filename-safe form of a target string. Replaces path-meaningful characters."""
    return target.replace("/", "_").replace(":", "_")


def _result_path(target: str, scanned_at: datetime) -> Path:
    ts = scanned_at.strftime("%Y%m%dT%H%M%SZ")
    return DISCOVERY_DIR / f"{_safe_target(target)}-{ts}.json"


def _write_result(result: DiscoveryResult) -> Path:
    """Serialize the DiscoveryResult to JSON, named by target + UTC timestamp."""
    DISCOVERY_DIR.mkdir(parents=True, exist_ok=True)
    out = _result_path(result.target, result.scanned_at)
    out.write_text(result.model_dump_json(indent=2))
    return out


def _write_manifest(result_path: Path, target: str) -> Path:
    """Write a sibling .manifest.json with sha256 + provenance, mirroring data/raw/*.manifest.json."""
    payload = result_path.read_bytes()
    digest = _sha256(payload)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    manifest = {
        "file": result_path.name,
        "sha256": digest,
        "ts": ts,
        "bytes": len(payload),
        "target": target,
    }
    manifest_path = result_path.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    log.info("discovery.manifest.written", **manifest)
    return manifest_path


def discover(target: str, max_assets: int = DEFAULT_MAX_ASSETS) -> DiscoveryResult:
    """Run subfinder + nmap end-to-end. Per-host failures are logged and skipped, not raised."""
    scanned_at = datetime.now(UTC)
    subdomains_all = enumerate_subdomains(target)
    log.info("discovery.subdomains.found", target=target, count=len(subdomains_all))

    # Always scan the target itself, in addition to its subdomains. Dedupe so a
    # subfinder result that already includes the apex doesn't get scanned twice.
    hosts_to_scan = [target] + [s for s in subdomains_all if s != target]

    if len(hosts_to_scan) > max_assets:
        log.info("discovery.truncated", had=len(hosts_to_scan), kept=max_assets)
        hosts_to_scan = hosts_to_scan[:max_assets]

    assets: list[Asset] = []
    for host in hosts_to_scan:
        try:
            ports = scan_host(host)
        except RuntimeError as e:
            log.warning("discovery.host.skipped", host=host, error=str(e))
            continue
        assets.append(Asset(hostname=host, ip=None, ports=ports, tls=None))

    tool_versions = {
        "subfinder": _subfinder_version(),
        "nmap": _nmap_version(),
    }

    result = DiscoveryResult(
        target=target,
        scanned_at=scanned_at,
        subdomains_found=len(subdomains_all),
        assets=assets,
        tool_versions=tool_versions,
    )
    result_path = _write_result(result)
    _write_manifest(result_path, target)
    log.info(
        "discovery.complete",
        target=target,
        assets=len(assets),
        path=str(result_path),
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Asset discovery: subfinder + nmap orchestration."
    )
    parser.add_argument("target", help="Apex domain to enumerate (e.g. example.com)")
    parser.add_argument(
        "--max-assets",
        type=int,
        default=DEFAULT_MAX_ASSETS,
        help=f"Cap subdomains scanned (default {DEFAULT_MAX_ASSETS})",
    )
    args = parser.parse_args()
    result = discover(args.target, max_assets=args.max_assets)
    print(_result_path(result.target, result.scanned_at))


if __name__ == "__main__":
    main()
