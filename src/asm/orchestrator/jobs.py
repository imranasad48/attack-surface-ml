"""In-memory ScanJob store + background-task runner.

Process restart loses all jobs. CLAUDE.md is explicit that there's no real queue
infrastructure for the local MVP — a real deployment would back this with Redis or
a DB-backed task queue.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from asm.orchestrator import pipeline
from asm.orchestrator.schemas import ScanJob

log = structlog.get_logger()

_JOBS: dict[str, ScanJob] = {}
_LOCK = threading.Lock()


def create_job(target: str) -> ScanJob:
    """Generate a UUID, store a pending ScanJob under that ID, return it."""
    now = datetime.now(UTC)
    job = ScanJob(
        job_id=str(uuid.uuid4()),
        target=target,
        status="pending",
        created_at=now,
        updated_at=now,
    )
    with _LOCK:
        _JOBS[job.job_id] = job
    log.info("scan.job.created", job_id=job.job_id, target=target)
    return job


def get_job(job_id: str) -> ScanJob | None:
    with _LOCK:
        return _JOBS.get(job_id)


def list_jobs() -> list[ScanJob]:
    with _LOCK:
        return list(_JOBS.values())


def update_job(job_id: str, **fields: Any) -> ScanJob | None:
    """Atomic update under the lock. ScanJob is frozen, so we model_copy + reassign."""
    with _LOCK:
        existing = _JOBS.get(job_id)
        if existing is None:
            return None
        updates = {**fields, "updated_at": datetime.now(UTC)}
        new_job = existing.model_copy(update=updates)
        _JOBS[job_id] = new_job
        return new_job


def run_scan_in_background(job_id: str) -> None:
    """Worker entry point. Catches every exception so a failure marks the job, not the process."""
    job = get_job(job_id)
    if job is None:
        log.error("scan.job.missing", job_id=job_id)
        return

    update_job(job_id, status="running")
    log.info("scan.job.running", job_id=job_id, target=job.target)

    try:
        result = pipeline.run_scan(job.target)
        update_job(job_id, status="completed", result=result)
        log.info("scan.job.completed", job_id=job_id)
    except Exception as e:
        update_job(job_id, status="failed", error=str(e))
        log.error("scan.job.failed", job_id=job_id, error=str(e))
