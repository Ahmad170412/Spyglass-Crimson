from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from spyglass.models import SourceContext, SourceError, SourceResult, Target

from ._active import primary_address, require_authorization, require_binary
from .base import Source

# Hard ceiling on ports per scan. ``--top-ports`` above this is refused rather
# than quietly running a much larger scan than the operator asked for.
MAX_TOP_PORTS = 1000


class NmapSource(Source):
    """Bounded TCP connect scan of one authorized host.

    Top N ports only (100 by default), no OS detection, no NSE scripts, no UDP,
    and no host discovery. The target is resolved and checked to be globally
    routable before nmap runs, and nmap is invoked as an argument list — never
    through a shell.
    """

    id = "nmap"
    label = "Port scan"
    layer = "aggressive"
    description = "TCP connect scan of the top 100 ports on one authorized host"
    accepts = ("domain", "ip")
    docs_url = "https://nmap.org/book/man.html"

    def target_address(self, target: Target) -> str:
        if target.kind == "ip" and target.ip is not None:
            if not target.ip.is_global:
                raise SourceError(f"Refusing to scan non-public address {target.ip}")
            return str(target.ip)
        return primary_address(target.host or target.value)

    def command(self, binary: str, address: str, ports: int, timeout: float) -> list[str]:
        return [
            binary,
            "-Pn",  # no host discovery: we already know the target
            "-n",  # no reverse DNS
            "-sT",  # TCP connect scan, works without root
            "-T3",
            "--top-ports",
            str(ports),
            "--max-retries",
            "1",
            "--host-timeout",
            f"{int(timeout)}s",
            "-oX",
            "-",
            address,
        ]

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        require_authorization(ctx, target)

        address = self.target_address(target)
        binary = require_binary("nmap", "nmap")
        timeout = max(1.0, float(ctx.settings.nmap_timeout))
        ports = max(1, min(int(ctx.settings.nmap_top_ports), MAX_TOP_PORTS))

        command = self.command(binary, address, ports, timeout)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SourceError(f"nmap timed out after {timeout:.0f}s") from exc
        except OSError as exc:
            raise SourceError(f"Could not execute nmap: {exc}") from exc

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip().splitlines()
            reason = stderr[-1] if stderr else f"exit code {completed.returncode}"
            raise SourceError(f"nmap failed: {reason}")

        return self.parse(completed.stdout, address, target, ports)

    def parse(
        self, xml_text: str, address: str, target: Target, ports: int
    ) -> SourceResult:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise SourceError(f"Could not parse nmap output: {exc}") from exc

        host = root.find("host")
        if host is None:
            payload = {
                "ip": address,
                "host": target.host,
                "host_up": False,
                "open_ports": [],
                "ports_scanned": ports,
            }
            return SourceResult(
                source=self.id,
                status="not_found",
                data=payload,
                record_count=0,
                provider="nmap",
            )

        status_el = host.find("status")
        host_up = status_el is not None and status_el.get("state") == "up"

        open_ports: list[dict[str, Any]] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            try:
                number = int(port.get("portid", "0"))
            except ValueError:
                continue
            open_ports.append(
                {
                    "port": number,
                    "protocol": port.get("protocol", "tcp"),
                    "service": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                }
            )

        payload = {
            "ip": address,
            "host": target.host,
            "host_up": host_up,
            "open_ports": open_ports,
            "open_port_count": len(open_ports),
            "ports_scanned": ports,
            "scanner": "nmap",
        }
        return SourceResult(
            source=self.id,
            status="ok" if open_ports else "empty",
            data=payload,
            record_count=len(open_ports),
            provider="nmap",
        )
