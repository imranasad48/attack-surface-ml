"""Pull EPSS daily feed. Hash every snapshot. Validate schema before persisting."""
from __future__ import annotations

import os
os.environ.setdefault("DISABLE_PANDERA_IMPORT_WARNING", "True")

import gzip
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pandas as pd
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from asm.data.validate import EPSSRecord

log = structlog.get_logger()
RAW = Path("data/raw")
PROCESSED = Path("data/processed")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_snapshot(name: str, payload: bytes) -> Path:
    """Write payload + manifest with sha256 + ISO timestamp. Provenance you can verify."""
    RAW.mkdir(parents=True, exist_ok=True)
    digest = _sha256(payload)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = RAW / f"{name}-{ts}.csv.gz"
    out.write_bytes(payload)
    manifest = {
        "file": out.name,
        "sha256": digest,
        "ts": ts,
        "bytes": len(payload),
        "source": EPSS_URL,
    }
    (RAW / f"{name}-{ts}.manifest.json").write_text(json.dumps(manifest, indent=2))
    log.info("snapshot.written", **manifest)
    return out


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
def _fetch(url: str) -> bytes:
    """Fetch with retries. Network failures shouldn't kill the pipeline on the first blip."""
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        r = client.get(url)
        r.raise_for_status()
        return r.content


def ingest_epss() -> Path:
    """Pull EPSS, snapshot it, validate schema, write a clean Parquet."""
    log.info("epss.fetch.start", url=EPSS_URL)
    payload = _fetch(EPSS_URL)
    snapshot_path = _write_snapshot("epss", payload)

    # Decompress + parse. EPSS CSV has a comment line on top; skip it.
    with gzip.open(snapshot_path, "rt") as f:
        df = pd.read_csv(f, comment="#")
    log.info("epss.parsed", rows=len(df), cols=list(df.columns))

    # Validate schema. If EPSS changes their format, we want to fail loud here, not silently downstream.
    EPSSRecord.validate(df, lazy=True)

    PROCESSED.mkdir(parents=True, exist_ok=True)
    out = PROCESSED / "epss.parquet"
    df.to_parquet(out, index=False)
    log.info("epss.written", path=str(out), rows=len(df))
    return out


def main() -> None:
    ingest_epss()


if __name__ == "__main__":
    main()