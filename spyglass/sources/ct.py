from __future__ import annotations

import re
from typing import Any

import httpx

from spyglass.cache import make_key
from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .base import Source

CRT_SH = "https://crt.sh/"
CERT_SPOTTER = "https://api.certspotter.com/v1/issuances"
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class CertificateTransparencySource(Source):
    id = "ct"
    label = "Certificate logs"
    layer = "core"
    description = "crt.sh certificate history, issuers, validity, and hostnames"
    accepts = ("domain",)
    docs_url = "https://crt.sh/"

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        if target.kind != "domain" or not target.host:
            raise SourceError("Certificate logs require a domain target")
        host = target.host
        cache_key = make_key("ct", host)
        cached = ctx.cache.get(cache_key)
        if isinstance(cached, dict):
            return _result_from_data(self.id, cached)

        errors: list[str] = []
        provider: str
        rows: list[dict[str, Any]]
        try:
            payload = ctx.http.get_json(
                CRT_SH,
                params={"q": f"%.{host}", "output": "json"},
                headers={"Accept": "application/json"},
            )
            rows = _normalize_crtsh(payload, host)
            provider = "crt.sh"
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"crt.sh: {exc}")
            try:
                payload = ctx.http.get_json(
                    CERT_SPOTTER,
                    params={
                        "domain": host,
                        "include_subdomains": "true",
                        "expand": ["dns_names", "issuer", "not_before", "not_after"],
                    },
                    headers={"Accept": "application/json"},
                )
                rows = _normalize_certspotter(payload, host)
                provider = "Cert Spotter"
            except (httpx.HTTPError, ValueError) as exc2:
                errors.append(f"Cert Spotter: {exc2}")
                raise SourceError("Certificate logs failed: " + "; ".join(errors)) from exc2

        if not rows:
            data = {
                "provider": provider,
                "certificates": [],
                "hostnames": [],
                "wildcards": [],
                "certificate_count": 0,
                "hostname_count": 0,
                "truncated": False,
                "errors": errors,
            }
            ctx.cache.set(cache_key, data, ctx.settings.ct_ttl)
            return SourceResult(source=self.id, status="empty", data=data, provider=provider)

        cert_limit = max(1, ctx.settings.max_ct_certs)
        name_limit = max(1, ctx.settings.max_ct_names)
        truncated = len(rows) > cert_limit
        certs = rows[:cert_limit]

        hostnames: list[str] = []
        wildcards: list[str] = []
        seen_hosts: set[str] = set()
        seen_wildcards: set[str] = set()
        for cert in certs:
            for name in cert.get("names", []):
                clean = _clean_candidate(name)
                if not clean:
                    continue
                if not _belongs_to(clean, host):
                    continue
                if clean.startswith("*."):
                    base = clean[2:]
                    if base and base not in seen_wildcards:
                        seen_wildcards.add(base)
                        wildcards.append(base)
                    continue
                if clean not in seen_hosts:
                    seen_hosts.add(clean)
                    hostnames.append(clean)

        hostnames.sort()
        wildcards.sort()
        if len(hostnames) > name_limit:
            hostnames = hostnames[:name_limit]
            truncated = True
        if len(wildcards) > name_limit:
            wildcards = wildcards[:name_limit]
            truncated = True

        data = {
            "provider": provider,
            "certificates": certs,
            "hostnames": hostnames,
            "wildcards": wildcards,
            "certificate_count": len(certs),
            "hostname_count": len(hostnames),
            "truncated": truncated,
            "errors": errors,
        }
        ctx.cache.set(cache_key, data, ctx.settings.ct_ttl)
        return SourceResult(
            source=self.id,
            status="partial" if errors else "ok",
            data=data,
            record_count=len(certs),
            errors={"crt.sh": errors[0]} if errors else {},
            truncated=truncated,
            provider=provider,
        )


def _normalize_crtsh(payload: Any, host: str) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        raise ValueError("crt.sh returned an unexpected response")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in payload:
        if not isinstance(row, dict):
            continue
        name_value = str(row.get("name_value") or "")
        names = _split_names(name_value)
        common_name = str(row.get("common_name") or "").strip().lower()
        if common_name:
            names = _split_names(common_name) + names
        names = sorted(set(names))
        if not names:
            continue
        cert_id = str(row.get("id") or "")
        key = cert_id or "|".join([str(row.get("issuer_name") or ""), *names])
        if key in seen:
            continue
        seen.add(key)
        output.append(
            {
                "id": cert_id or None,
                "common_name": common_name or None,
                "names": names,
                "issuer": _issuer_name(row.get("issuer_name") or row.get("issuer")),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
            }
        )
    return output


def _normalize_certspotter(payload: Any, host: str) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        raise ValueError("Cert Spotter returned an unexpected response")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in payload:
        if not isinstance(row, dict):
            continue
        names = sorted(
            {
                name.strip().lower().rstrip(".")
                for name in row.get("dns_names") or []
                if isinstance(name, str) and name.strip()
            }
        )
        if not names:
            continue
        cert_id = str(row.get("id") or "")
        issuer = row.get("issuer")
        if isinstance(issuer, dict):
            issuer = issuer.get("name") or issuer.get("friendly_name")
        key = cert_id or "|".join([str(issuer or ""), *names])
        if key in seen:
            continue
        seen.add(key)
        output.append(
            {
                "id": cert_id or None,
                "common_name": names[0],
                "names": names,
                "issuer": _issuer_name(issuer),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
            }
        )
    return output


def _split_names(value: str) -> list[str]:
    return [
        name.strip().lower().rstrip(".")
        for name in value.replace("\r", "\n").split("\n")
        if name.strip()
    ]


def _clean_candidate(name: str) -> str | None:
    value = str(name).strip().lower().rstrip(".")
    if not value or "@" in value or " " in value:
        return None
    wildcard = value.startswith("*.")
    probe = value[2:] if wildcard else value
    if not _HOST_RE.match(probe):
        return None
    return value


def _belongs_to(name: str, host: str) -> bool:
    probe = name[2:] if name.startswith("*.") else name
    return probe == host or probe.endswith("." + host)


def _issuer_name(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("name") or value.get("friendly_name")
    if not value:
        return None
    return str(value)


def _result_from_data(source: str, data: dict[str, Any]) -> SourceResult:
    certs = data.get("certificates") or []
    return SourceResult(
        source=source,
        status="ok" if certs else "empty",
        data=data,
        record_count=int(data.get("certificate_count") or 0),
        truncated=bool(data.get("truncated")),
        provider=data.get("provider"),
    )
