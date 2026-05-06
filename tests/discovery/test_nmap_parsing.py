"""Nmap XML parsing — no live binary, just monkeypatched subprocess.run."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from asm.discovery import nmap

NMAP_XML_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -p 22,80,443 -oX - example.com" version="7.80">
<host>
  <status state="up"/>
  <address addr="93.184.216.34" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="6.6.1p1">
        <cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe>
      </service>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="Apache httpd" version="2.4.7">
        <cpe>cpe:/a:apache:http_server:2.4.7</cpe>
      </service>
    </port>
    <port protocol="tcp" portid="443">
      <state state="closed"/>
      <service name="https"/>
    </port>
  </ports>
</host>
</nmaprun>"""


def _completed(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def test_scan_host_returns_open_ports_with_service_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(NMAP_XML_FIXTURE))
    ports = nmap.scan_host("example.com")
    assert len(ports) == 2  # closed port dropped
    by_port = {p.port: p for p in ports}

    assert by_port[22].protocol == "tcp"
    assert by_port[22].state == "open"
    assert by_port[22].service == "ssh"
    assert by_port[22].product == "OpenSSH"
    assert by_port[22].version == "6.6.1p1"
    assert by_port[22].cpe == "cpe:/a:openbsd:openssh:6.6.1p1"

    assert by_port[80].service == "http"
    assert by_port[80].product == "Apache httpd"
    assert by_port[80].version == "2.4.7"
    assert by_port[80].cpe == "cpe:/a:apache:http_server:2.4.7"


def test_scan_host_drops_closed_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _completed(NMAP_XML_FIXTURE))
    ports = nmap.scan_host("example.com")
    assert {p.port for p in ports} == {22, 80}  # 443 was closed, excluded


def test_missing_binary_raises_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*a: Any, **kw: Any) -> Any:
        raise FileNotFoundError("nmap")

    monkeypatch.setattr(subprocess, "run", _raise)
    with pytest.raises(RuntimeError, match="nmap not on PATH"):
        nmap.scan_host("example.com")
