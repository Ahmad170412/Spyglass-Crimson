from __future__ import annotations

import httpx

from spyglass.cache import make_key
from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .base import Source

INTERNETDB = "https://internetdb.shodan.io"


class InternetDbSource(Source):
    id = "internetdb"
    label = "Shodan InternetDB"
    layer = "core"
    description = "Keyless host exposure from Shodan's weekly InternetDB dataset"
    accepts = ("ip",)
    docs_url = "https://internetdb.shodan.io/"
    key_env = None

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        if target.kind != "ip" or target.ip is None:
            raise SourceError("InternetDB requires a single IP")
        address = str(target.ip)
        cache_key = make_key("internetdb", address)
        cached = ctx.cache.get(cache_key)
        if isinstance(cached, dict):
            return _result(self.id, cached)

        try:
            response = ctx.http.get(f"{INTERNETDB}/{address}")
        except httpx.HTTPError as exc:
            raise SourceError(f"InternetDB failed: {exc}") from exc

        if response.status_code == 404:
            data = {
                "ip": address,
                "ports": [],
                "hostnames": [],
                "tags": [],
                "cpes": [],
                "vulns": [],
                "status": "not_found",
            }
            ctx.cache.set(cache_key, data, ctx.settings.internetdb_ttl)
            return SourceResult(
                source=self.id,
                status="not_found",
                data=data,
                record_count=0,
                provider="InternetDB",
            )
        if response.status_code != 200:
            raise SourceError(f"InternetDB returned HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise SourceError("InternetDB returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise SourceError("InternetDB returned an unexpected response")
        ports = sorted({int(port) for port in payload.get("ports") or [] if str(port).isdigit()})
        data = {
            "ip": str(payload.get("ip") or address),
            "ports": ports,
            "hostnames": sorted(
                {str(item).lower().rstrip(".") for item in payload.get("hostnames") or [] if item}
            ),
            "tags": sorted({str(item) for item in payload.get("tags") or [] if item}),
            "cpes": sorted({str(item) for item in payload.get("cpes") or [] if item}),
            "vulns": sorted({str(item) for item in payload.get("vulns") or [] if item}),
            "status": "ok",
        }
        ctx.cache.set(cache_key, data, ctx.settings.internetdb_ttl)
        return _result(self.id, data)


def _result(source: str, data: dict) -> SourceResult:
    count = len(data.get("ports") or []) + len(data.get("hostnames") or [])
    status = "ok" if data.get("status") == "ok" else "not_found"
    return SourceResult(
        source=source,
        status=status,
        data=data,
        record_count=count,
        provider="InternetDB",
    )
