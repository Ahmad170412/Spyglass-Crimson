from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import Target

ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ValidationError(ValueError):
    """The target is not something the tool accepts."""


@dataclass(frozen=True)
class NetworkExpansion:
    addresses: list[str]
    total: int
    truncated: bool


def _strip_url(value: str) -> str | None:
    raw = value.strip()
    if not raw:
        return None
    if raw.startswith("//"):
        raw = "http:" + raw
    elif "://" not in raw and any(ch in raw for ch in "/?#@") or (
        "://" not in raw and ":" in raw and not raw.startswith("[")
    ):
        raw = "http://" + raw
    if "://" not in raw:
        return None
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"}:
        return None
    if parsed.username or parsed.password:
        return None
    return parsed.hostname


def normalize_domain(value: str) -> str:
    host = value.strip().lower()
    if host.startswith("["):
        raise ValidationError("IPv6 addresses must be entered as IP targets")
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise ValidationError("Enter a domain or URL")
    if host.startswith(".") or ".." in host:
        raise ValidationError("Invalid domain")
    if len(host) > 253:
        raise ValidationError("Domain is too long")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError("Invalid internationalized domain") from exc
    labels = ascii_host.split(".")
    if len(labels) < 2:
        raise ValidationError("Enter a domain with a public suffix")
    for label in labels:
        if not LABEL_RE.match(label):
            raise ValidationError("Invalid domain label")
    # A bare hostname with a single label is not useful for passive OSINT.
    return ascii_host


def parse_website(value: str) -> Target:
    raw = value.strip()
    if not raw:
        raise ValidationError("Enter a domain or URL")
    host = _strip_url(raw)
    if host is None:
        host = raw
    host = normalize_domain(host)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValidationError("Use a domain, not an IP, for website recon")
    return Target(kind="domain", value=host, raw=raw, host=host)


def parse_ip_target(value: str) -> Target:
    raw = value.strip()
    if not raw:
        raise ValidationError("Enter an IP, CIDR, or ASN")
    asn_match = ASN_RE.match(raw)
    if asn_match:
        asn = int(asn_match.group(1))
        if asn < 1 or asn > 4294967295:
            raise ValidationError("ASN is out of range")
        return Target(kind="asn", value=f"AS{asn}", raw=raw, asn=asn)
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValidationError("Invalid CIDR range") from exc
        if network.prefixlen == 0:
            raise ValidationError("A /0 range is too broad")
        return Target(kind="cidr", value=str(network), raw=raw, network=network)
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ValidationError("Enter a valid IP, CIDR, or ASN") from exc
    return Target(kind="ip", value=str(address), raw=raw, ip=address)


def parse_target(value: str, mode: str = "ip") -> Target:
    if mode == "website":
        return parse_website(value)
    return parse_ip_target(value)


def expand_network(network, limit: int = 25) -> NetworkExpansion:
    """Return at most `limit` usable addresses from a CIDR, deterministically."""
    if limit < 1:
        return NetworkExpansion(addresses=[], total=0, truncated=False)
    if network.version == 4:
        total = network.num_addresses
        if network.prefixlen <= 30:
            total = max(0, total - 2)
        iterator = network.hosts() if network.prefixlen <= 30 else iter(network)
    else:
        total = network.num_addresses
        iterator = network
    addresses: list[str] = []
    for address in iterator:
        if len(addresses) >= limit:
            break
        addresses.append(str(address))
    truncated = total > len(addresses)
    return NetworkExpansion(addresses=addresses, total=total, truncated=truncated)


def reverse_pointer(address: str) -> str:
    try:
        return ipaddress.ip_address(address).reverse_pointer
    except ValueError as exc:
        raise ValidationError("Invalid IP address") from exc
