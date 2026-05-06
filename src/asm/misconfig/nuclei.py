"""Wrap nuclei binary. Run misconfiguration templates against a list of hosts. Parses JSON Lines output to Finding objects."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import structlog

from asm.misconfig.schemas import Finding

log = structlog.get_logger()

NUCLEI_TIMEOUT = 600  # seconds; nuclei misconfig scans can be slow over many hosts
DEFAULT_TEMPLATE_PATH = os.environ.get(
    "NUCLEI_TEMPLATES_PATH",
    str(Path.home() / "nuclei-templates" / "http" / "misconfiguration"),
)
DEFAULT_SEVERITIES = "low,medium,high,critical"  # info is too noisy for production reports
_VERSION_RE = re.compile(r"version[:\s]+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


def scan_hosts(
    hosts: list[str],
    template_path: str | None = None,
    severities: str = DEFAULT_SEVERITIES,
) -> list[Finding]:
    """Run nuclei against `hosts` with misconfig templates and return findings."""
    template_path = template_path or DEFAULT_TEMPLATE_PATH
    log.info("misconfig.nuclei.start", hosts=len(hosts), template_path=template_path)

    # nuclei -u takes a single host; -l takes a file. Always use -l for consistency.
    with tempfile.NamedTemporaryFile(
        mode="w", delete=False, suffix=".txt", encoding="utf-8"
    ) as f:
        f.write("\n".join(hosts))
        host_list_path = f.name

    try:
        # check=False: nuclei exits non-zero when findings exist, which isn't a tool error
        result = subprocess.run(  # noqa: S603, S607
            [
                "nuclei",
                "-l",
                host_list_path,
                "-t",
                template_path,
                "-severity",
                severities,
                "-silent",
                "-jsonl",
            ],
            timeout=NUCLEI_TIMEOUT,
            capture_output=True,
            check=False,
            text=True,
        )
    except FileNotFoundError as e:
        log.error("misconfig.tool.missing", tool="nuclei")
        raise RuntimeError(
            "nuclei not on PATH; install from "
            "https://github.com/projectdiscovery/nuclei/releases/latest"
        ) from e
    except subprocess.TimeoutExpired as e:
        log.error("misconfig.nuclei.error", reason="timeout")
        raise RuntimeError(
            f"nuclei timed out after {NUCLEI_TIMEOUT}s for {len(hosts)} hosts"
        ) from e
    finally:
        Path(host_list_path).unlink(missing_ok=True)

    findings: list[Finding] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        findings.append(_parse_finding(json.loads(line)))

    log.info("misconfig.nuclei.done", hosts=len(hosts), findings=len(findings))
    return findings


def _parse_finding(raw: dict[str, Any]) -> Finding:
    """Map one nuclei -jsonl record to a Finding. Defensive — every nested field may be missing or null."""
    info = raw.get("info") or {}
    classification = info.get("classification") or {}

    host = raw.get("host")
    if not host and raw.get("url"):
        parsed = urlparse(str(raw["url"]))
        host = parsed.hostname or str(raw["url"])
    if not host:
        host = "unknown"

    ts_raw = raw.get("timestamp")
    timestamp = (
        datetime.fromisoformat(ts_raw) if isinstance(ts_raw, str) else datetime.now(UTC)
    )

    return Finding(
        template_id=raw.get("template-id", ""),
        name=info.get("name", ""),
        severity=info.get("severity", "info"),
        host=host,
        matched_at=raw.get("matched-at", ""),
        description=info.get("description"),
        tags=info.get("tags") or [],
        cwe_ids=classification.get("cwe-id") or [],
        cvss_score=classification.get("cvss-score"),
        extracted_results=raw.get("extracted-results") or [],
        timestamp=timestamp,
    )


def _nuclei_version() -> str:
    """Best-effort nuclei version probe. Returns 'vX.Y.Z' or 'unknown' on any failure."""
    try:
        result = subprocess.run(  # noqa: S603, S607
            ["nuclei", "-version"],
            timeout=10,
            capture_output=True,
            check=False,
            text=True,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"
    output = result.stdout + "\n" + result.stderr
    match = _VERSION_RE.search(output)
    return f"v{match.group(1)}" if match else "unknown"
