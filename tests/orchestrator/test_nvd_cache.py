"""SQLite cache hit/miss + batch shape for the NVD lookup module."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest

from asm.orchestrator import nvd


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeClient:
    """Minimal httpx.Client stand-in. Counts get() calls so tests can assert cache hits."""

    calls = 0
    payload_for: ClassVar[dict[str, dict[str, Any]]] = {}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def get(self, url: str, headers: dict[str, str], params: dict[str, str]) -> _FakeResponse:
        type(self).calls += 1
        cpe = params["cpeName"]
        return _FakeResponse(type(self).payload_for.get(cpe, {"vulnerabilities": []}))


@pytest.fixture
def fresh_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point the cache at an empty tmp_path SQLite + stub out HTTP and rate-limit sleep."""
    monkeypatch.setattr(nvd, "NVD_CACHE_DB", tmp_path / "nvd_cache.db")
    monkeypatch.setattr(nvd.time, "sleep", lambda _s: None)
    _FakeClient.calls = 0
    _FakeClient.payload_for = {}
    monkeypatch.setattr(httpx, "Client", _FakeClient)


def test_repeat_lookup_hits_cache(fresh_cache: None) -> None:
    """Two calls for the same CPE produce exactly one HTTP request — the second is cached."""
    cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    _FakeClient.payload_for[cpe] = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2021-41773"}},
            {"cve": {"id": "CVE-2021-42013"}},
        ]
    }

    first = nvd.lookup_cves_for_cpe(cpe)
    second = nvd.lookup_cves_for_cpe(cpe)

    assert first == ["CVE-2021-41773", "CVE-2021-42013"]
    assert second == first
    assert _FakeClient.calls == 1, "second lookup must come from the cache"


def test_batch_lookup_returns_per_cpe_dict(fresh_cache: None) -> None:
    """Three CPEs (one pre-cached) — output dict keyed by CPE with the right CVE lists."""
    cpe_a = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    cpe_b = "cpe:2.3:a:openssh:openssh:8.2p1:*:*:*:*:*:*:*"
    cpe_c = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

    _FakeClient.payload_for[cpe_a] = {"vulnerabilities": [{"cve": {"id": "CVE-2021-23017"}}]}
    _FakeClient.payload_for[cpe_b] = {"vulnerabilities": []}
    _FakeClient.payload_for[cpe_c] = {"vulnerabilities": [{"cve": {"id": "CVE-2021-41773"}}]}

    # Pre-warm cache for cpe_c
    nvd.lookup_cves_for_cpe(cpe_c)
    assert _FakeClient.calls == 1

    result = nvd.lookup_cves_for_cpes([cpe_a, cpe_b, cpe_c])

    assert set(result.keys()) == {cpe_a, cpe_b, cpe_c}
    assert result[cpe_a] == ["CVE-2021-23017"]
    assert result[cpe_b] == []
    assert result[cpe_c] == ["CVE-2021-41773"]
    # 1 prewarm + 2 misses (cpe_a, cpe_b); cpe_c served from cache
    assert _FakeClient.calls == 3


def test_cpe22_to_cpe23_conversion() -> None:
    """nmap emits CPE 2.2; NVD requires 2.3 — convert before the HTTP call."""
    assert nvd._to_cpe_23("cpe:/a:openbsd:openssh:6.6.1p1") == "cpe:2.3:a:openbsd:openssh:6.6.1p1:*:*:*:*:*:*:*"
    assert nvd._to_cpe_23("cpe:/a:apache:http_server:2.4.7") == "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*"


def test_cpe23_passthrough() -> None:
    """A CPE already in 2.3 form is returned unchanged."""
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    assert nvd._to_cpe_23(cpe) == cpe


def test_cpe_unparseable_returns_original() -> None:
    """Unrecognized input is returned as-is so NVD's 404 surfaces instead of a silent rewrite."""
    junk = "not-a-cpe-at-all"
    assert nvd._to_cpe_23(junk) == junk
