from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .base import Source
from .asn import AsnSource
from .censys import CensysSource
from .ct import CertificateTransparencySource
from .dns import DnsSource
from .http_probe import HttpProbeSource
from .internetdb import InternetDbSource
from .ipinfo import IpinfoSource
from .nmap import NmapSource
from .nuclei import NucleiSource
from .otx import OtxSource
from .ptr import PtrSource
from .rdap import RdapSource
from .shodan import ShodanSource
from .spamhaus import SpamhausDropSource
from .subdomains import SubdomainsSource
from .tor import TorExitSource
from .urlscan import UrlscanSource
from .wayback import WaybackSource


@dataclass(frozen=True)
class SourceMeta:
    id: str
    label: str
    layer: str
    description: str
    accepts: tuple[str, ...]
    requires_key: bool = False
    implemented: bool = True
    derived_from: tuple[str, ...] = ()
    docs_url: str = ""
    key_env: str | None = None
    requires_binary: str | None = None

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "layer": self.layer,
            "description": self.description,
            "accepts": list(self.accepts),
            "requires_key": self.requires_key,
            "implemented": self.implemented,
            "derived_from": list(self.derived_from),
            "docs_url": self.docs_url,
            "requires_binary": self.requires_binary,
        }


ADAPTERS: dict[str, type[Source]] = {
    "rdap": RdapSource,
    "dns": DnsSource,
    "ct": CertificateTransparencySource,
    "subdomains": SubdomainsSource,
    "asn": AsnSource,
    "ptr": PtrSource,
    "internetdb": InternetDbSource,
    "wayback": WaybackSource,
    "tor": TorExitSource,
    "spamhaus": SpamhausDropSource,
    "shodan": ShodanSource,
    "censys": CensysSource,
    "ipinfo": IpinfoSource,
    "otx": OtxSource,
    "urlscan": UrlscanSource,
    "http": HttpProbeSource,
    "nmap": NmapSource,
    "nuclei": NucleiSource,
}

META: tuple[SourceMeta, ...] = (
    SourceMeta(
        id="rdap",
        label="WHOIS / RDAP",
        layer="core",
        description="Registration, registrar, dates, status, nameservers, and DNSSEC",
        accepts=("domain", "ip"),
        docs_url="https://www.iana.org/assignments/rdap/rdap.xhtml",
    ),
    SourceMeta(
        id="dns",
        label="DNS records",
        layer="core",
        description="A, AAAA, NS, MX, TXT/SPF, CAA, SOA, and DMARC through DoH",
        accepts=("domain",),
        docs_url="https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
    ),
    SourceMeta(
        id="ct",
        label="Certificate logs",
        layer="core",
        description="crt.sh certificate history with a Cert Spotter fallback",
        accepts=("domain",),
        docs_url="https://crt.sh/",
    ),
    SourceMeta(
        id="subdomains",
        label="Subdomains",
        layer="core",
        description="Unique hostnames derived from certificate transparency logs",
        accepts=("domain",),
        derived_from=("ct",),
        docs_url="https://crt.sh/",
    ),
    SourceMeta(
        id="asn",
        label="ASN & routing",
        layer="core",
        description="Origin ASN, announced prefix, country, registry, and AS name",
        accepts=("ip", "asn"),
        docs_url="https://stat.ripe.net/docs/02.data-api/",
    ),
    SourceMeta(
        id="ptr",
        label="Reverse DNS",
        layer="core",
        description="PTR records for an address through DNS-over-HTTPS",
        accepts=("ip",),
        docs_url="https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
    ),
    SourceMeta(
        id="internetdb",
        label="Shodan InternetDB",
        layer="core",
        description="Keyless ports, hostnames, tags, and CVEs from Shodan's weekly dataset",
        accepts=("ip",),
        docs_url="https://internetdb.shodan.io/",
    ),
    SourceMeta(
        id="wayback",
        label="Historical URLs",
        layer="core",
        description="Archived URLs and historical hosts from the Wayback CDX index",
        accepts=("domain",),
        docs_url="https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server",
    ),
    SourceMeta(
        id="tor",
        label="Tor exits",
        layer="core",
        description="Whether an IPv4 address is a current Tor exit node",
        accepts=("ip",),
        docs_url="https://www.torproject.org/",
    ),
    SourceMeta(
        id="spamhaus",
        label="Spamhaus DROP",
        layer="core",
        description="Hijacked and bulletproof-hosting netblocks from Spamhaus DROP",
        accepts=("ip",),
        docs_url="https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
    ),
    SourceMeta(
        id="shodan",
        label="Shodan API",
        layer="enrichment",
        description="Banner and service detail; InternetDB remains the keyless default",
        accepts=("ip",),
        requires_key=True,
        implemented=True,
        docs_url="https://developer.shodan.io/api",
        key_env="SPYGLASS_SHODAN_KEY",
    ),
    SourceMeta(
        id="censys",
        label="Censys",
        layer="enrichment",
        description="Opt-in host and certificate index lookups with a credit cap",
        accepts=("ip", "domain"),
        requires_key=True,
        implemented=True,
        docs_url="https://search.censys.io/api",
        key_env="SPYGLASS_CENSYS_KEY",
    ),
    SourceMeta(
        id="ipinfo",
        label="IPinfo Lite",
        layer="enrichment",
        description="ASN, country, and continent enrichment",
        accepts=("ip",),
        requires_key=True,
        implemented=True,
        docs_url="https://ipinfo.io/developers",
        key_env="SPYGLASS_IPINFO_TOKEN",
    ),
    SourceMeta(
        id="otx",
        label="AlienVault OTX",
        layer="enrichment",
        description="Passive DNS history for subdomain pivots",
        accepts=("domain", "ip"),
        requires_key=True,
        implemented=True,
        docs_url="https://otx.alienvault.com/api",
        key_env="SPYGLASS_OTX_KEY",
    ),
    SourceMeta(
        id="urlscan",
        label="urlscan.io",
        layer="enrichment",
        description="Historical page scans and metadata",
        accepts=("domain",),
        requires_key=True,
        implemented=True,
        docs_url="https://urlscan.io/docs/api/",
        key_env="SPYGLASS_URLSCAN_KEY",
    ),
    SourceMeta(
        id="http",
        label="HTTP probe",
        layer="aggressive",
        description="One authorized HTTPS request: status, headers, title, and redirect",
        accepts=("domain", "ip"),
        implemented=True,
    ),
    SourceMeta(
        id="nmap",
        label="Port scan",
        layer="aggressive",
        description="TCP connect scan of the top 100 ports on one authorized host",
        accepts=("domain", "ip"),
        implemented=True,
        docs_url="https://nmap.org/book/man.html",
        requires_binary="nmap",
    ),
    SourceMeta(
        id="nuclei",
        label="Template checks",
        layer="aggressive",
        description="Rate-limited, non-intrusive template checks on one authorized host",
        accepts=("domain", "ip"),
        implemented=True,
        docs_url="https://docs.projectdiscovery.io/tools/nuclei/overview",
        requires_binary="nuclei",
    ),
)

META_BY_ID = {item.id: item for item in META}


def get_source(source_id: str) -> Source:
    try:
        adapter = ADAPTERS[source_id]
    except KeyError as exc:
        raise KeyError(f"Unknown source: {source_id}") from exc
    return adapter()


def source_meta(source_id: str) -> SourceMeta:
    try:
        return META_BY_ID[source_id]
    except KeyError as exc:
        raise KeyError(f"Unknown source: {source_id}") from exc


def sources_for(
    kind: str, *, layer: str | None = None, include_aggressive: bool = False
) -> list[SourceMeta]:
    """Sources that accept this target kind.

    Aggressive adapters are excluded unless the caller has already checked the
    authorization gate — planning one by accident must not send traffic.
    """
    return [
        item
        for item in META
        if kind in item.accepts
        and item.implemented
        and (layer is None or item.layer == layer)
        and (include_aggressive or item.layer != "aggressive")
    ]


def all_meta() -> Iterable[SourceMeta]:
    return META
