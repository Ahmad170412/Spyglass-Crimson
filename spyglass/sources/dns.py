from __future__ import annotations

import re
from typing import Any

from spyglass.doh import DohError, answer_rows, clean_name, decode_txt, doh_query
from spyglass.models import SourceContext, SourceError, SourceResult, Target
from spyglass.validation import ValidationError, parse_website

from .base import Source

RECORD_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "CAA", "SOA", "CNAME")
TYPE_CODES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
CAA_RE = re.compile(r'^(\d+)\s+(\S+)\s+"?([^"]*)"?$')


class DnsSource(Source):
    id = "dns"
    label = "DNS records"
    layer = "core"
    description = "A, AAAA, NS, MX, TXT/SPF, CAA, SOA, and DMARC through DoH"
    accepts = ("domain",)
    docs_url = "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/"

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        if target.kind != "domain" or not target.host:
            raise SourceError("DNS requires a domain target")
        try:
            host = parse_website(target.host).host or target.host
        except ValidationError as exc:
            raise SourceError(str(exc)) from exc

        records: dict[str, list[Any]] = {rtype: [] for rtype in RECORD_TYPES}
        txt_chunks: list[str] = []
        errors: dict[str, str] = {}
        providers: set[str] = set()
        nxdomain = 0
        queried = 0

        for rtype in RECORD_TYPES:
            queried += 1
            try:
                data = doh_query(ctx, host, rtype, ttl=ctx.settings.dns_ttl)
            except DohError as exc:
                errors[rtype] = str(exc)
                continue
            providers.add(str(data.get("_provider", "unknown")))
            if data.get("Status") == 3:
                nxdomain += 1
            for row in answer_rows(data):
                if row.get("type") not in (None, TYPE_CODES[rtype]):
                    continue
                value = str(row.get("data", "")).strip()
                if not value:
                    continue
                if rtype == "A" or rtype == "AAAA":
                    records[rtype].append(value)
                elif rtype == "NS":
                    records[rtype].append(clean_name(value))
                elif rtype == "CNAME":
                    records[rtype].append(clean_name(value))
                elif rtype == "MX":
                    parsed = _parse_mx(value)
                    if parsed:
                        records[rtype].append(parsed)
                elif rtype == "TXT":
                    decoded = decode_txt(value)
                    txt_chunks.append(decoded)
                    records[rtype].append(decoded)
                elif rtype == "CAA":
                    parsed = _parse_caa(value)
                    if parsed:
                        records[rtype].append(parsed)
                elif rtype == "SOA":
                    parsed = _parse_soa(value)
                    if parsed:
                        records[rtype].append(parsed)

        dmarc_name = f"_dmarc.{host}"
        dmarc_records: list[str] = []
        queried += 1
        try:
            data = doh_query(ctx, dmarc_name, "TXT", ttl=ctx.settings.dns_ttl)
            providers.add(str(data.get("_provider", "unknown")))
            for row in answer_rows(data):
                if row.get("type") not in (None, TYPE_CODES["TXT"]):
                    continue
                decoded = decode_txt(str(row.get("data", "")))
                if decoded:
                    dmarc_records.append(decoded)
        except DohError as exc:
            errors["DMARC"] = str(exc)

        spf = next((value for value in txt_chunks if value.lower().startswith("v=spf1")), None)
        dmarc = next((value for value in dmarc_records if value.upper().startswith("V=DMARC1")), None)
        records["DMARC"] = dmarc_records

        if queried and len(errors) == queried:
            raise SourceError("DNS lookups failed: " + "; ".join(errors.values()))

        record_count = sum(len(values) for values in records.values())
        if nxdomain and record_count == 0:
            status = "not_found"
        elif errors:
            status = "partial"
        elif record_count == 0:
            status = "empty"
        else:
            status = "ok"

        data = {
            "host": host,
            "records": records,
            "spf": spf,
            "dmarc": dmarc,
            "resolver": "mixed" if len(providers) > 1 else (next(iter(providers), None)),
            "errors": errors,
        }
        return SourceResult(
            source=self.id,
            status=status,
            data=data,
            record_count=record_count,
            errors=errors,
            provider="DoH",
        )


def _parse_mx(value: str) -> dict[str, Any] | None:
    parts = value.split()
    if len(parts) < 2:
        return None
    try:
        priority = int(parts[0])
    except ValueError:
        return None
    return {"priority": priority, "host": clean_name(parts[1])}


def _parse_caa(value: str) -> dict[str, Any] | None:
    match = CAA_RE.match(value)
    if not match:
        return None
    return {
        "flags": int(match.group(1)),
        "tag": match.group(2).lower(),
        "value": match.group(3),
    }


def _parse_soa(value: str) -> dict[str, Any] | None:
    parts = value.split()
    if len(parts) < 7:
        return None
    fields = ("mname", "rname", "serial", "refresh", "retry", "expire", "minimum")
    result: dict[str, Any] = {}
    for field, part in zip(fields, parts):
        if field in {"mname", "rname"}:
            result[field] = clean_name(part)
        else:
            try:
                result[field] = int(part)
            except ValueError:
                result[field] = part
    return result
