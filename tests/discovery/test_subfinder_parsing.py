"""Subfinder output parsing — no live binary, just monkeypatched subprocess.run."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from asm.discovery import subfinder


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_enumerate_subdomains_parses_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = "api.example.com\nwww.example.com\nmail.example.com\n"
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(fake))
    assert subfinder.enumerate_subdomains("example.com") == [
        "api.example.com",
        "www.example.com",
        "mail.example.com",
    ]


def test_enumerate_subdomains_drops_blank_and_whitespace_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = "\napi.example.com\n   \nwww.example.com\n\n"
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(fake))
    assert subfinder.enumerate_subdomains("example.com") == [
        "api.example.com",
        "www.example.com",
    ]


def test_missing_binary_raises_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*a: Any, **kw: Any) -> Any:
        raise FileNotFoundError("subfinder")

    monkeypatch.setattr(subprocess, "run", _raise)
    with pytest.raises(RuntimeError, match="subfinder not on PATH"):
        subfinder.enumerate_subdomains("example.com")


def test_timeout_raises_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*a: Any, **kw: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="subfinder", timeout=1)

    monkeypatch.setattr(subprocess, "run", _raise)
    with pytest.raises(RuntimeError, match="timed out"):
        subfinder.enumerate_subdomains("example.com")
