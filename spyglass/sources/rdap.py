from __future__ import annotations

import ipaddress
import shutil
import subprocess
from typing import Any
from urllib.parse import quote

import httpx

from spyglass.cache import make_key
from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .base import Source

BOOTSTRAP = {
    "domain": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
}
RDAP_FALLBACK = "https://rdap.org"
EVENT_KEYS = {
    "registration": "registered",
    "expiration": "expires",
    "last changed": "updated",
    "last update of rdap database": "rdap_updated",
}


class RdapSource(Source):
    id = "rdap"
    label = "WHOIS / RDAP"
    layer = "core"
    description = "Registration data, registrar, dates, status, nameservers, and DNSSEC"
    accepts = ("domain", "ip")
    docs_url = "https://www.iana.org/assignments/rdap/rdap.xhtml"

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        if target.kind == "domain" and target.host:
            return self._domain(target.host, ctx)
        if target.kind == "ip" and target.ip is not None:
            return self._ip(target.ip, ctx)
        raise SourceError("RDAP requires a domain or single IP")

    def _domain(self, host: str, ctx: SourceContext) -> SourceResult:
        tld = host.rsplit(".", 1)[-1].lower()
        base = _bootstrap_base(ctx, "domain", tld)
        urls = [u for u in (base, RDAP_FALLBACK) if u]
        for base_url in urls:
            if not base_url:
                continue
            url = f"{base_url.rstrip('/')}/domain/{quote(host)}"
            try:
                payload = _rdap_json(ctx, url, ctx.settings.rdap_ttl)
            except (httpx.HTTPError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            data = _normalize_domain(host, payload)
            if base_url == RDAP_FALLBACK:
                data["provider"] = "rdap.org"
            return SourceResult(
                source=self.id,
                status="ok",
                data=data,
                record_count=1,
                provider=data.get("provider", "RDAP"),
            )
        text = _whois(host)
        if text:
            data = _parse_whois_domain(host, text)
            if data.get("name") or data.get("registrar") or data.get("nameservers"):
                return SourceResult(
                    source=self.id,
                    status="ok",
                    data=data,
                    record_count=1,
                    provider="whois",
                )
        raise SourceError(f"No RDAP or WHOIS record found for {host}")

    def _ip(self, address, ctx: SourceContext) -> SourceResult:
        family = "ipv6" if address.version == 6 else "ipv4"
        base = _bootstrap_base(ctx, family, address)
        urls = [u for u in (base, RDAP_FALLBACK) if u]
        for base_url in urls:
            if not base_url:
                continue
            url = f"{base_url.rstrip('/')}/ip/{address}"
            try:
                payload = _rdap_json(ctx, url, ctx.settings.rdap_ttl)
            except (httpx.HTTPError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            data = _normalize_ip(address, payload)
            if base_url == RDAP_FALLBACK:
                data["provider"] = "rdap.org"
            return SourceResult(
                source=self.id,
                status="ok",
                data=data,
                record_count=1,
                provider=data.get("provider", "RDAP"),
            )
        raise SourceError(f"No RDAP network record found for {address}")


def _bootstrap_base(ctx: SourceContext, kind: str, key: Any) -> str | None:
    cache_key = make_key("rdap", "bootstrap", kind)
    try:
        payload = ctx.http.get_json(
            BOOTSTRAP[kind],
            cache=ctx.cache,
            ttl=ctx.settings.bootstrap_ttl,
            cache_key=cache_key,
        )
    except (httpx.HTTPError, ValueError):
        return None
    services = payload.get("services") if isinstance(payload, dict) else None
    if not isinstance(services, list):
        return None
    if kind == "domain":
        tld = str(key).lower()
        for service in services:
            if not isinstance(service, list) or len(service) < 2:
                continue
            keys, urls = service[0], service[1]
            if tld in {str(item).lower() for item in keys} and urls:
                return str(urls[0])
        return None

    address = key
    best: tuple[int, str] | None = None
    for service in services:
        if not isinstance(service, list) or len(service) < 2:
            continue
        keys, urls = service[0], service[1]
        if not urls:
            continue
        for item in keys:
            try:
                network = ipaddress.ip_network(str(item), strict=False)
            except ValueError:
                continue
            if network.version != address.version or address not in network:
                continue
            if best is None or network.prefixlen > best[0]:
                best = (network.prefixlen, str(urls[0]))
    return best[1] if best else None


def _rdap_json(ctx: SourceContext, url: str, ttl: int) -> Any:
    return ctx.http.get_json(
        url,
        headers={"Accept": "application/rdap+json, application/json"},
        cache=ctx.cache,
        ttl=ttl,
        cache_key=make_key("rdap", url),
    )


def _normalize_domain(host: str, payload: dict[str, Any]) -> dict[str, Any]:
    events = _events(payload.get("events"))
    registrar, abuse = _registrar(payload.get("entities"))
    nameservers = []
    for item in payload.get("nameservers") or []:
        if isinstance(item, dict):
            name = item.get("ldhName") or item.get("unicodeName")
            if name:
                nameservers.append(str(name).lower().rstrip("."))
    secure = payload.get("secureDNS") or {}
    dnssec = secure.get("delegationSigned") if isinstance(secure, dict) else None
    return {
        "provider": "RDAP",
        "handle": payload.get("handle"),
        "name": (payload.get("ldhName") or payload.get("unicodeName") or host).lower(),
        "status": payload.get("status") or [],
        "registrar": registrar,
        "abuse_email": abuse,
        "events": events,
        "nameservers": sorted(set(nameservers)),
        "dnssec": bool(dnssec) if dnssec is not None else None,
    }


def _normalize_ip(address, payload: dict[str, Any]) -> dict[str, Any]:
    events = _events(payload.get("events"))
    org, abuse = _registrar(payload.get("entities"))
    if org is None:
        org = _organization(payload.get("entities"))
    start = payload.get("startAddress")
    end = payload.get("endAddress")
    cidrs: list[str] = []
    if start and end:
        try:
            cidrs = [
                str(net)
                for net in ipaddress.summarize_address_range(
                    ipaddress.ip_address(str(start)), ipaddress.ip_address(str(end))
                )
            ]
        except ValueError:
            cidrs = []
    return {
        "provider": "RDAP",
        "ip": str(address),
        "handle": payload.get("handle"),
        "name": payload.get("name"),
        "start": start,
        "end": end,
        "cidrs": cidrs,
        "type": payload.get("type"),
        "country": payload.get("country"),
        "parent": payload.get("parentHandle"),
        "status": payload.get("status") or [],
        "organization": org,
        "abuse_email": abuse,
        "events": events,
        "remarks": [
            str(remark.get("description"))
            for remark in payload.get("remarks") or []
            if isinstance(remark, dict) and remark.get("description")
        ],
    }


def _events(items: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items or []:
        if not isinstance(item, dict):
            continue
        action = str(item.get("eventAction", "")).strip().lower()
        key = EVENT_KEYS.get(action)
        if key and item.get("eventDate"):
            result[key] = str(item["eventDate"])
    return result


def _vcard(entity: dict[str, Any]) -> dict[str, Any]:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return {}
    fields: dict[str, Any] = {}
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        name, _params, _type, value = item[0], item[1], item[2], item[3]
        if name in {"fn", "org", "email", "adr"}:
            if name == "adr" and isinstance(value, list):
                value = ", ".join(str(part) for part in value if part)
            fields.setdefault(name, []).append(value)
    return fields


def _walk_entities(entities: Any):
    for entity in entities or []:
        if not isinstance(entity, dict):
            continue
        yield entity
        yield from _walk_entities(entity.get("entities"))


def _registrar(entities: Any) -> tuple[dict[str, Any] | None, str | None]:
    registrar: dict[str, Any] | None = None
    abuse_email: str | None = None
    for entity in _walk_entities(entities):
        roles = [str(role).lower() for role in entity.get("roles") or []]
        fields = _vcard(entity)
        if "registrar" in roles and registrar is None:
            names = fields.get("fn") or fields.get("org") or []
            registrar = {
                "name": names[0] if names else entity.get("handle"),
                "handle": entity.get("handle"),
                "iana_id": _public_id(entity),
            }
        if "abuse" in roles and abuse_email is None:
            emails = fields.get("email") or []
            if emails:
                abuse_email = str(emails[0])
    return registrar, abuse_email


def _organization(entities: Any) -> dict[str, Any] | None:
    for entity in _walk_entities(entities):
        roles = [str(role).lower() for role in entity.get("roles") or []]
        if not any(role in roles for role in ("registrant", "administrative", "technical")):
            continue
        fields = _vcard(entity)
        names = fields.get("fn") or fields.get("org") or []
        if names:
            return {"name": names[0], "handle": entity.get("handle"), "iana_id": None}
    return None


def _public_id(entity: dict[str, Any]) -> str | None:
    for item in entity.get("publicIds") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("type", "")).lower() in {"iana registrar id", "iana"}:
            return str(item.get("identifier"))
    return None


def _whois(host: str) -> str | None:
    executable = shutil.which("whois")
    if not executable:
        return None
    try:
        completed = subprocess.run(
            [executable, host],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    return completed.stdout[:40000]


def _parse_whois_domain(host: str, text: str) -> dict[str, Any]:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        if ":" not in line or line.lstrip().startswith("%"):
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        fields.setdefault(key, []).append(value)
    nameservers = sorted(
        {
            value.split()[0].lower().rstrip(".")
            for key in ("name server", "nserver")
            for value in fields.get(key, [])
            if value.split()
        }
    )
    status = sorted(
        set(fields.get("domain status", []) + fields.get("status", []))
    )
    registered = _first(fields, "creation date", "created", "registered")
    expires = _first(fields, "registry expiry date", "expiry date", "expiration date")
    updated = _first(fields, "updated date", "last modified")
    registrar_name = _first(fields, "registrar", "sponsoring registrar")
    dnssec_raw = _first(fields, "dnssec")
    dnssec = None
    if dnssec_raw:
        dnssec = "unsigned" not in dnssec_raw.lower()
    return {
        "provider": "whois",
        "handle": None,
        "name": (_first(fields, "domain name") or host).lower(),
        "status": status,
        "registrar": {"name": registrar_name, "handle": None, "iana_id": None}
        if registrar_name
        else None,
        "abuse_email": _first(fields, "abuse-mailbox", "abuse email"),
        "events": {
            "registered": registered,
            "expires": expires,
            "updated": updated,
        },
        "nameservers": nameservers,
        "dnssec": dnssec,
    }


def _first(fields: dict[str, list[str]], *keys: str) -> str | None:
    for key in keys:
        values = fields.get(key)
        if values:
            return values[0]
    return None
