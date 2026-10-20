from __future__ import annotations

import ipaddress
from typing import Any

import httpx

from spyglass.cache import make_key
from spyglass.doh import DohError, answer_rows, decode_txt, doh_query
from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .base import Source

RIPESTAT = "https://stat.ripe.net/data"
CYMRU_V4 = "origin.asn.cymru.com"
CYMRU_V6 = "origin6.asn.cymru.com"


class AsnSource(Source):
    id = "asn"
    label = "ASN & routing"
    layer = "core"
    description = "Origin ASN, announced prefix, country, registry, and AS name"
    accepts = ("ip", "asn")
    docs_url = "https://stat.ripe.net/docs/02.data-api/"

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        if target.kind == "ip" and target.ip is not None:
            return self._for_ip(target.ip, ctx)
        if target.kind == "asn" and target.asn is not None:
            return self._for_asn(target.asn, ctx)
        raise SourceError("ASN lookup requires a single IP or ASN")

    def _for_ip(self, address, ctx: SourceContext) -> SourceResult:
        cache_key = make_key("asn", "ip", str(address))
        cached = ctx.cache.get(cache_key)
        if isinstance(cached, dict):
            return _ip_result(self.id, cached)

        cymru: dict[str, Any] | None = None
        cymru_error: str | None = None
        try:
            cymru = _cymru(address, ctx)
        except DohError as exc:
            cymru_error = str(exc)

        if cymru and cymru["asns"]:
            asn = cymru["asns"][0]
            as_name = _as_name(asn, ctx) if asn else None
            data = {
                "ip": str(address),
                "asn": asn,
                "asns": cymru["asns"],
                "as_name": as_name,
                "prefix": cymru["prefix"],
                "prefixes": [cymru["prefix"]] if cymru["prefix"] else [],
                "country": cymru["country"],
                "registry": cymru["registry"],
                "allocated": cymru["allocated"],
                "source": "Team Cymru",
            }
            ctx.cache.set(cache_key, data, ctx.settings.routing_ttl)
            return _ip_result(self.id, data)

        network, ripestat_error = _ripestat_network(address, ctx)
        if network is not None:
            asn = network["asns"][0] if network["asns"] else None
            data = {
                "ip": str(address),
                "asn": asn,
                "asns": network["asns"],
                "as_name": _as_name(asn, ctx) if asn else None,
                "prefix": network["prefix"],
                "prefixes": [network["prefix"]] if network["prefix"] else [],
                "country": None,
                "registry": None,
                "allocated": None,
                "source": "RIPEstat",
            }
            ctx.cache.set(cache_key, data, ctx.settings.routing_ttl)
            if network["asns"]:
                return _ip_result(self.id, data)
            return SourceResult(source=self.id, status="empty", data=data, provider="RIPEstat")

        errors = {}
        if cymru_error:
            errors["team-cymru"] = cymru_error
        if ripestat_error:
            errors["ripestat"] = ripestat_error
        if errors:
            raise SourceError("ASN lookup failed: " + "; ".join(errors.values()))
        return SourceResult(
            source=self.id,
            status="empty",
            data={"ip": str(address), "asn": None, "asns": [], "source": None},
            provider=None,
        )

    def _for_asn(self, asn: int, ctx: SourceContext) -> SourceResult:
        cache_key = make_key("asn", "asn", str(asn))
        cached = ctx.cache.get(cache_key)
        if isinstance(cached, dict):
            return _asn_result(self.id, cached)

        errors: dict[str, str] = {}
        as_name = None
        prefixes: list[str] = []
        try:
            overview = ctx.http.get_json(
                f"{RIPESTAT}/as-overview/data.json",
                params={"resource": f"AS{asn}"},
                cache=ctx.cache,
                ttl=ctx.settings.routing_ttl,
                cache_key=make_key("ripestat", "as-overview", str(asn)),
            )
            as_name = (overview.get("data") or {}).get("holder")
        except (httpx.HTTPError, ValueError) as exc:
            errors["as-overview"] = str(exc)
        try:
            announced = ctx.http.get_json(
                f"{RIPESTAT}/announced-prefixes/data.json",
                params={"resource": f"AS{asn}"},
                cache=ctx.cache,
                ttl=ctx.settings.routing_ttl,
                cache_key=make_key("ripestat", "announced-prefixes", str(asn)),
            )
            rows = (announced.get("data") or {}).get("prefixes") or []
            prefixes = sorted(
                {
                    str(row.get("prefix"))
                    for row in rows
                    if isinstance(row, dict) and row.get("prefix")
                }
            )
        except (httpx.HTTPError, ValueError) as exc:
            errors["announced-prefixes"] = str(exc)

        limit = max(1, ctx.settings.max_asn_prefixes)
        truncated = len(prefixes) > limit
        prefixes = prefixes[:limit]
        if not as_name and not prefixes and errors:
            raise SourceError("ASN lookup failed: " + "; ".join(errors.values()))
        data = {
            "asn": asn,
            "as_name": as_name,
            "prefixes": prefixes,
            "prefix_count": len(prefixes),
            "truncated": truncated,
            "source": "RIPEstat",
            "errors": errors,
        }
        ctx.cache.set(cache_key, data, ctx.settings.routing_ttl)
        return _asn_result(self.id, data, errors=errors)


def _cymru(address, ctx: SourceContext) -> dict[str, Any] | None:
    name = _cymru_name(address)
    data = doh_query(ctx, name, "TXT", ttl=ctx.settings.routing_ttl)
    parsed: list[dict[str, str]] = []
    for row in answer_rows(data):
        value = decode_txt(str(row.get("data", "")))
        for line in value.splitlines():
            parts = [part.strip() for part in line.split("|")]
            if len(parts) < 2:
                continue
            parsed.append(
                {
                    "asns": parts[0],
                    "prefix": parts[1],
                    "country": parts[2] if len(parts) > 2 else "",
                    "registry": parts[3] if len(parts) > 3 else "",
                    "allocated": parts[4] if len(parts) > 4 else "",
                }
            )
    if not parsed:
        return None
    first = parsed[0]
    asns = []
    for value in " ".join(item["asns"] for item in parsed).split():
        if value.isdigit() and int(value) not in asns:
            asns.append(int(value))
    prefix = first["prefix"]
    if prefix and "/" in prefix:
        try:
            ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            prefix = ""
    return {
        "asns": asns,
        "prefix": prefix,
        "country": first["country"] or None,
        "registry": first["registry"] or None,
        "allocated": first["allocated"] or None,
    }


def _cymru_name(address) -> str:
    if address.version == 4:
        reversed_octets = ".".join(reversed(str(address).split(".")))
        return f"{reversed_octets}.{CYMRU_V4}"
    nibbles = address.exploded.replace(":", "")
    return f"{'.'.join(reversed(nibbles))}.{CYMRU_V6}"


def _ripestat_network(address, ctx: SourceContext) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = ctx.http.get_json(
            f"{RIPESTAT}/network-info/data.json",
            params={"resource": str(address)},
            cache=ctx.cache,
            ttl=ctx.settings.routing_ttl,
            cache_key=make_key("ripestat", "network-info", str(address)),
        )
    except (httpx.HTTPError, ValueError) as exc:
        return None, str(exc)
    data = payload.get("data") or {}
    asns = []
    for value in data.get("asns") or []:
        try:
            asns.append(int(value))
        except (TypeError, ValueError):
            continue
    return {"asns": asns, "prefix": data.get("prefix")}, None


def _as_name(asn: int | None, ctx: SourceContext) -> str | None:
    if not asn:
        return None
    try:
        payload = ctx.http.get_json(
            f"{RIPESTAT}/as-overview/data.json",
            params={"resource": f"AS{asn}"},
            cache=ctx.cache,
            ttl=ctx.settings.routing_ttl,
            cache_key=make_key("ripestat", "as-overview", str(asn)),
        )
    except (httpx.HTTPError, ValueError):
        return None
    return (payload.get("data") or {}).get("holder")


def _ip_result(source: str, data: dict[str, Any]) -> SourceResult:
    return SourceResult(
        source=source,
        status="ok" if data.get("asn") else "empty",
        data=data,
        record_count=1 if data.get("asn") else 0,
        provider=data.get("source"),
    )


def _asn_result(
    source: str,
    data: dict[str, Any],
    *,
    errors: dict[str, str] | None = None,
) -> SourceResult:
    status = "ok" if data.get("prefixes") or data.get("as_name") else "empty"
    if errors:
        status = "partial" if status == "ok" else status
    return SourceResult(
        source=source,
        status=status,
        data=data,
        record_count=int(data.get("prefix_count") or 0),
        errors=errors or {},
        truncated=bool(data.get("truncated")),
        provider="RIPEstat",
    )
