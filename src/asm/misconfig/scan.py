"""Orchestrate misconfiguration scanning. Run nuclei against a list of hosts, write a hash-validated MisconfigResult."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import structlog

from asm.misconfig.nuclei import DEFAULT_SEVERITIES, _nuclei_version, scan_hosts
from asm.misconfig.schemas import MisconfigResult

log = structlog.get_logger()

MISCONFIG_DIR = Path("data/misconfig")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _result_path(ts: str) -> Path:
    return MISCONFIG_DIR / f"misconfig-{ts}.json"


def _write_result(result: MisconfigResult, ts: str) -> Path:
    """Serialize the MisconfigResult to JSON, named misconfig-<ts>.json."""
    MISCONFIG_DIR.mkdir(parents=True, exist_ok=True)
    out = _result_path(ts)
    out.write_text(result.model_dump_json(indent=2))
    return out


def _write_manifest(result_path: Path, ts: str) -> Path:
    """Write a sibling .manifest.json with sha256 + provenance.

    Reads the result back to derive n_targets so the manifest is a faithful
    receipt of file contents — same role as `target` in discovery's manifest.
    """
    payload = result_path.read_bytes()
    digest = _sha256(payload)
    result = MisconfigResult.model_validate_json(payload)
    manifest = {
        "file": result_path.name,
        "sha256": digest,
        "ts": ts,
        "bytes": len(payload),
        "n_targets": len(result.targets),
    }
    manifest_path = result_path.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    log.info("misconfig.manifest.written", **manifest)
    return manifest_path


def scan(hosts: list[str], severities: str | None = None) -> MisconfigResult:
    """Run nuclei across `hosts`. Empty list short-circuits — nuclei is not invoked."""
    if not hosts:
        log.info("misconfig.nothing_to_scan")
        return MisconfigResult(
            scanned_at=datetime.now(UTC),
            targets=[],
            findings=[],
            tool_versions={},
        )

    findings = scan_hosts(hosts, severities=severities or DEFAULT_SEVERITIES)

    result = MisconfigResult(
        scanned_at=datetime.now(UTC),
        targets=hosts,
        findings=findings,
        tool_versions={"nuclei": _nuclei_version()},
    )

    ts = result.scanned_at.strftime("%Y%m%dT%H%M%SZ")
    result_path = _write_result(result, ts)
    _write_manifest(result_path, ts)
    log.info(
        "misconfig.complete",
        targets=len(hosts),
        findings=len(findings),
        path=str(result_path),
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Misconfiguration scan: nuclei orchestration over a list of hosts."
    )
    parser.add_argument("hosts", nargs="+", help="One or more hosts to scan")
    parser.add_argument(
        "--severities",
        default=DEFAULT_SEVERITIES,
        help=f"Comma-separated nuclei severity filter (default {DEFAULT_SEVERITIES})",
    )
    args = parser.parse_args()
    result = scan(args.hosts, severities=args.severities)
    ts = result.scanned_at.strftime("%Y%m%dT%H%M%SZ")
    print(_result_path(ts))


if __name__ == "__main__":
    main()
