"""Wrap nmap binary. Port scan + service version detection. Outputs structured PortInfo objects via XML."""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET

import structlog

from asm.discovery.schemas import PortInfo

log = structlog.get_logger()

NMAP_PORTS = "22,80,443,8080,3306,5432,6379,8443,27017"
NMAP_TIMEOUT = 300  # seconds; a wedged host can hang an unbounded scan otherwise
_VERSION_RE = re.compile(r"Nmap version (\d+\.\d+(?:\.\d+)?)")


def scan_host(host: str, ports: str = NMAP_PORTS) -> list[PortInfo]:
    """Run nmap -sV against `host` on `ports`; return only state=open as PortInfo."""
    log.info("nmap.start", host=host, ports=ports)
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-p", ports, "-oX", "-", host],
            timeout=NMAP_TIMEOUT,
            capture_output=True,
            check=True,
            text=True,
        )
    except FileNotFoundError as e:
        log.error("discovery.tool.missing", tool="nmap")
        raise RuntimeError(
            "nmap not on PATH; install from https://nmap.org/download.html"
        ) from e
    except subprocess.TimeoutExpired as e:
        log.error("nmap.error", host=host, exit_code=None)
        raise RuntimeError(f"nmap timed out after {NMAP_TIMEOUT}s for {host}") from e
    except subprocess.CalledProcessError as e:
        log.error("nmap.error", host=host, exit_code=e.returncode)
        raise RuntimeError(f"nmap failed for {host} (exit {e.returncode})") from e

    ports_open = _parse_xml(result.stdout)
    log.info("nmap.done", host=host, open_ports=len(ports_open))
    return ports_open


def _parse_xml(xml_str: str) -> list[PortInfo]:
    """Parse `nmap -oX` stdout. Drops non-open ports — they don't help CVE matching."""
    root = ET.fromstring(xml_str)  # noqa: S314 — trusted nmap output, not external XML
    out: list[PortInfo] = []
    for port_el in root.iter("port"):
        state_el = port_el.find("state")
        state = state_el.get("state", "") if state_el is not None else ""
        if state != "open":
            continue
        portid = int(port_el.get("portid", "0"))
        protocol = port_el.get("protocol", "")
        service_el = port_el.find("service")
        if service_el is not None:
            service = service_el.get("name") or None
            product = service_el.get("product") or None
            version = service_el.get("version") or None
            cpe_el = service_el.find("cpe")
            cpe = cpe_el.text if cpe_el is not None else None
        else:
            service = product = version = cpe = None
        out.append(
            PortInfo(
                port=portid,
                protocol=protocol,
                state=state,
                service=service,
                product=product,
                version=version,
                cpe=cpe,
            )
        )
    return out


def _nmap_version() -> str:
    """Best-effort nmap version probe. Returns 'unknown' on any failure."""
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            timeout=10,
            capture_output=True,
            check=False,
            text=True,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"
    match = _VERSION_RE.search(result.stdout)
    return match.group(1) if match else "unknown"
