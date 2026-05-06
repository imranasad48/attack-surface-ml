"""ScanJob store: round-trip, concurrent updates, success/failure marking."""

from __future__ import annotations

import threading
from datetime import UTC, datetime

import pytest

from asm.orchestrator import jobs, pipeline
from asm.orchestrator.schemas import UnifiedScanResult


@pytest.fixture(autouse=True)
def _clear_jobs() -> None:
    """Each test starts with an empty in-memory store."""
    jobs._JOBS.clear()


def test_create_and_get_round_trip() -> None:
    job = jobs.create_job("example.com")
    fetched = jobs.get_job(job.job_id)

    assert fetched is not None
    assert fetched.job_id == job.job_id
    assert fetched.target == "example.com"
    assert fetched.status == "pending"
    assert fetched.result is None
    assert fetched.error is None


def test_get_unknown_job_returns_none() -> None:
    assert jobs.get_job("does-not-exist") is None


def test_update_job_atomic_under_concurrent_calls() -> None:
    """10 threads writing distinct error strings — final state is consistent, no exceptions."""
    job = jobs.create_job("example.com")
    n_threads = 10
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            jobs.update_job(job.job_id, error=f"thread-{i}")
        except BaseException as e:  # noqa: BLE001 — capture any thread-side failure
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"thread(s) raised: {errors}"
    final = jobs.get_job(job.job_id)
    assert final is not None
    assert final.error in {f"thread-{i}" for i in range(n_threads)}
    assert final.updated_at >= job.created_at


def test_run_scan_in_background_marks_completed_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_result = UnifiedScanResult(
        target="example.com",
        scanned_at=datetime.now(UTC),
        status="completed",
        assets=[],
        aggregate_summary={"total_assets": 0},
        tool_versions={},
    )
    monkeypatch.setattr(pipeline, "run_scan", lambda target: fake_result)

    job = jobs.create_job("example.com")
    jobs.run_scan_in_background(job.job_id)

    final = jobs.get_job(job.job_id)
    assert final is not None
    assert final.status == "completed"
    assert final.result is not None
    assert final.result.target == "example.com"


def test_run_scan_in_background_marks_failed_on_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(target: str) -> UnifiedScanResult:
        raise RuntimeError("pipeline exploded")

    monkeypatch.setattr(pipeline, "run_scan", boom)

    job = jobs.create_job("example.com")
    jobs.run_scan_in_background(job.job_id)

    final = jobs.get_job(job.job_id)
    assert final is not None
    assert final.status == "failed"
    assert final.error == "pipeline exploded"
    assert final.result is None


def test_run_scan_in_background_unknown_job_is_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Calling the worker with a missing job_id must not raise — just log + return."""
    called = False

    def fake_run(target: str) -> UnifiedScanResult:
        nonlocal called
        called = True
        raise AssertionError("pipeline must not run for a missing job")

    monkeypatch.setattr(pipeline, "run_scan", fake_run)

    jobs.run_scan_in_background("not-a-real-id")
    assert called is False
