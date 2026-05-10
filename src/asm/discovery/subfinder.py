"""Wrap subfinder binary. Enumerate subdomains passively from public sources."""

from __future__ import annotations

import re
import subprocess

import structlog

log = structlog.get_logger()

SUBFINDER_TIMEOUT = 180  # seconds; passive sources can be slow
_VERSION_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?)")


def enumerate_subdomains(target: str) -> list[str]:
    """Return discovered subdomains for `target`. Raises RuntimeError on tool failure or timeout."""
    log.info("subfinder.start", target=target)
    try:
        result = subprocess.run(
            ["subfinder", "-d", target, "-silent", "-timeout", "60"],
            timeout=SUBFINDER_TIMEOUT,
            capture_output=True,
            check=True,
            text=True,
        )
    except FileNotFoundError as e:
        log.error("discovery.tool.missing", tool="subfinder")
        raise RuntimeError("subfinder not on PATH; install from https://github.com/projectdiscovery/subfinder") from e
    except subprocess.TimeoutExpired as e:
        log.error("subfinder.error", target=target, exit_code=None)
        raise RuntimeError(f"subfinder timed out after {SUBFINDER_TIMEOUT}s for {target}") from e
    except subprocess.CalledProcessError as e:
        log.error("subfinder.error", target=target, exit_code=e.returncode)
        raise RuntimeError(f"subfinder failed for {target} (exit {e.returncode})") from e

    subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    log.info("subfinder.done", target=target, count=len(subdomains))
    return subdomains


def _subfinder_version() -> str:
    """Best-effort version probe. Returns 'unknown' on any failure."""
    try:
        result = subprocess.run(
            ["subfinder", "-version"],
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
