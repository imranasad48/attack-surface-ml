"""CPE → CVE-ID lookup against the NVD REST API, with SQLite caching.

First scan is slow (one HTTP per unique CPE); subsequent scans hit cache.
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from asm.config import Settings, get_settings

log = structlog.get_logger()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 30  # per request, seconds
NVD_CACHE_DB = Path("data/orchestrator/nvd_cache.db")
NVD_RATE_LIMIT_NO_KEY = 6.0  # seconds between requests without key
NVD_RATE_LIMIT_WITH_KEY = 0.6  # seconds between requests with key

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cpe_cve_cache (
    cpe TEXT PRIMARY KEY,
    cve_ids TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    hit_count INTEGER DEFAULT 1
);
"""


def _init_cache_db() -> None:
    """Ensure parent dir exists and the cache table is created. Idempotent."""
    NVD_CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(NVD_CACHE_DB) as conn:
        conn.execute(_CREATE_TABLE_SQL)
        conn.commit()


def _cache_get(cpe: str) -> list[str] | None:
    """Return cached CVE-ID list for `cpe`, incrementing hit_count. None on miss."""
    _init_cache_db()
    with sqlite3.connect(NVD_CACHE_DB) as conn:
        row = conn.execute(
            "SELECT cve_ids, hit_count FROM cpe_cve_cache WHERE cpe = ?", (cpe,)
        ).fetchone()
        if row is None:
            return None
        cve_ids_json, hit_count = row
        conn.execute(
            "UPDATE cpe_cve_cache SET hit_count = ? WHERE cpe = ?",
            (hit_count + 1, cpe),
        )
        conn.commit()
        cve_ids: list[str] = json.loads(cve_ids_json)
        log.info("nvd.cache.hit", cpe=cpe, count=hit_count + 1)
        return cve_ids


def _cache_put(cpe: str, cve_ids: list[str]) -> None:
    """Insert (or replace) a cache entry. Resets hit_count to 1."""
    _init_cache_db()
    with sqlite3.connect(NVD_CACHE_DB) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO cpe_cve_cache (cpe, cve_ids, fetched_at, hit_count) "
            "VALUES (?, ?, ?, 1)",
            (cpe, json.dumps(cve_ids), datetime.now(UTC).isoformat()),
        )
        conn.commit()


def _to_cpe_23(cpe: str) -> str:
    """Convert CPE 2.2 (`cpe:/a:vendor:product:version`) to 2.3 (`cpe:2.3:a:...:*:*:*:*:*:*:*`).

    nmap emits 2.2; the NVD REST API only accepts 2.3. Pass-through if already 2.3.
    Unparseable input is returned unchanged so a 404 surfaces from NVD instead of
    a silent conversion bug.
    """
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if cpe.startswith("cpe:/"):
        tail = cpe[len("cpe:/") :]
        parts = tail.split(":")
        if len(parts) >= 4:
            part, vendor, product, version = parts[0], parts[1], parts[2], parts[3]
            return f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    log.warning("nvd.cpe.unparseable", cpe=cpe)
    return cpe


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
def _http_fetch(cpe: str, settings: Settings) -> list[str]:
    """One HTTP GET to NVD. Re-raises on error; tenacity wraps for retries."""
    headers: dict[str, str] = {}
    if settings.nvd_api_key:
        # NVD's documented header for API-key auth is `apiKey`, not Authorization.
        headers["apiKey"] = settings.nvd_api_key
    params = {"cpeName": _to_cpe_23(cpe)}
    try:
        with httpx.Client(timeout=NVD_TIMEOUT) as client:
            response = client.get(NVD_API_BASE, headers=headers, params=params)
            response.raise_for_status()
    except httpx.HTTPError as e:
        log.error("nvd.error", cpe=cpe, error=str(e))
        raise
    payload: dict[str, Any] = response.json()
    vulns = payload.get("vulnerabilities", [])
    cve_ids = [v["cve"]["id"] for v in vulns if "cve" in v and "id" in v.get("cve", {})]
    return cve_ids


def lookup_cves_for_cpe(cpe: str, settings: Settings | None = None) -> list[str]:
    """CPE → list of CVE-IDs. Cache-first; on miss, rate-limited HTTP fetch + cache write."""
    if settings is None:
        settings = get_settings()

    cached = _cache_get(cpe)
    if cached is not None:
        return cached

    log.info("nvd.cache.miss", cpe=cpe)
    log.info("nvd.lookup.start", cpe=cpe)
    delay = NVD_RATE_LIMIT_WITH_KEY if settings.nvd_api_key else NVD_RATE_LIMIT_NO_KEY
    time.sleep(delay)

    cve_ids = _http_fetch(cpe, settings)
    _cache_put(cpe, cve_ids)
    log.info("nvd.fetch.done", cpe=cpe, n_cves=len(cve_ids))
    return cve_ids


def lookup_cves_for_cpes(
    cpes: list[str], settings: Settings | None = None
) -> dict[str, list[str]]:
    """Batch over `cpes` (deduped). Returns {cpe: [cve_ids]}. Reuses cache between entries."""
    if settings is None:
        settings = get_settings()

    unique_cpes = list(dict.fromkeys(cpes))  # preserve order, dedupe
    log.info("nvd.batch.start", n=len(unique_cpes))

    out: dict[str, list[str]] = {}
    cache_hits = 0
    total_cves = 0
    for cpe in unique_cpes:
        # Probe the cache first so we can count hits without a second SQL round-trip.
        # The lookup function re-checks; that second probe is also a hit on the same row.
        if _cache_peek(cpe):
            cache_hits += 1
        cve_ids = lookup_cves_for_cpe(cpe, settings=settings)
        out[cpe] = cve_ids
        total_cves += len(cve_ids)

    log.info(
        "nvd.batch.done",
        n=len(unique_cpes),
        total_cves=total_cves,
        cache_hits=cache_hits,
    )
    return out


def _cache_peek(cpe: str) -> bool:
    """Read-only existence check used for batch metrics. Does not increment hit_count."""
    _init_cache_db()
    with sqlite3.connect(NVD_CACHE_DB) as conn:
        row = conn.execute(
            "SELECT 1 FROM cpe_cve_cache WHERE cpe = ?", (cpe,)
        ).fetchone()
    return row is not None
