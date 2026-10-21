from __future__ import annotations

import ipaddress
import shutil
import socket

from spyglass.models import SourceContext, SourceError, Target


def require_authorization(ctx: SourceContext, target: Target) -> None:
    """Every active module refuses unless the gate is open for this target.

    The orchestrator checks this before planning and again before running. The
    check lives here too so a module can never be executed directly by mistake.
    """
    from spyglass.orchestrator import gate_allows_aggressive

    if not gate_allows_aggressive(ctx.settings, target.value):
        raise SourceError(
            "Active modules require a recorded authorization for this target"
        )


def public_addresses(host: str) -> list[str]:
    """Resolve a host and refuse anything that is not globally routable."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SourceError(f"Could not resolve {host}: {exc}") from exc

    addresses: list[str] = []
    for info in infos:
        raw = info[4][0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if not address.is_global:
            raise SourceError(f"Refusing to touch non-public address {address}")
        if str(address) not in addresses:
            addresses.append(str(address))
    if not addresses:
        raise SourceError(f"Could not resolve {host} to a public address")
    return addresses


def primary_address(host: str) -> str:
    """Pick one public address, preferring IPv4 for scanner compatibility."""
    addresses = public_addresses(host)
    for address in addresses:
        if ":" not in address:
            return address
    return addresses[0]


def require_binary(name: str, label: str) -> str:
    path = shutil.which(name)
    if not path:
        raise SourceError(f"{label} is not installed or not on PATH")
    return path
