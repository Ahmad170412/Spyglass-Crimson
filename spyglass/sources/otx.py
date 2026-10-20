from __future__ import annotations

from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .keyed import KeyedSource

OTX = "https://otx.alienvault.com/api/v1"


class OtxSource(KeyedSource):
    id = "otx"
    label = "AlienVault OTX"
    layer = "enrichment"
    description = "Passive DNS history for subdomain pivots"
    accepts = ("domain", "ip")
    requires_key = True
    docs_url = "https://otx.alienvault.com/api"
    key_env = "SPYGLASS_OTX_KEY"
    provider = "otx"

    def request_url(self, target: Target) -> str:
        if target.kind == "ip":
            return f"{OTX}/indicators/IPv4/{target.value}/passive_dns"
        return f"{OTX}/indicators/domain/{target.value}/passive_dns"

    def auth_headers(self, key: str) -> dict[str, str]:
        return {"X-OTX-API-KEY": key}

    def fetch(self, target: Target, ctx: SourceContext, key):
        return ctx.http.get(
            self.request_url(target),
            headers=self.auth_headers(key),
            timeout=self.timeout(ctx),
        )

    def timeout(self, ctx: SourceContext):
        return ctx.settings.http_timeout

    def normalize(self, target: Target, payload: object) -> SourceResult:
        if not isinstance(payload, dict):
            raise SourceError("OTX returned an unexpected response")
        records = payload.get("passive_dns") or []
        rows = []
        hosts: set[str] = set()
        first: str | None = None
        last: str | None = None
        for item in records:
            if not isinstance(item, dict):
                continue
            hostname = str(item.get("hostname") or "").lower().rstrip(".")
            address = str(item.get("address") or "")
            last_seen = str(item.get("last") or "")
            first_seen = str(item.get("first") or "")
            if hostname:
                hosts.add(hostname)
            if last_seen and (last is None or last_seen > last):
                last = last_seen
            if first_seen and (first is None or first_seen < first):
                first = first_seen
            rows.append(
                {
                    "hostname": hostname or None,
                    "address": address or None,
                    "first_seen": first_seen or None,
                    "last_seen": last_seen or None,
                    "record_type": item.get("record_type"),
                    "asn": item.get("asn"),
                }
            )
        data = {
            "target": target.value,
            "records": rows,
            "hosts": sorted(hosts),
            "host_count": len(hosts),
            "first_seen": first,
            "last_seen": last,
            "status": "ok" if rows else "empty",
            "record_count": len(rows),
        }
        return SourceResult(
            source=self.id,
            status="ok" if rows else "empty",
            data=data,
            record_count=len(rows),
            provider=self.label,
        )

    def ttl(self, ctx: SourceContext) -> int:
        return ctx.settings.ct_ttl

    def test_key(self, ctx: SourceContext) -> tuple[bool, str]:
        key = self.api_key(ctx)
        response = ctx.http.get(
            f"{OTX}/_pulse/subscribed",
            headers=self.auth_headers(key),
            timeout=ctx.settings.http_timeout,
        )
        if response.status_code in {401, 403}:
            return False, "Key rejected by AlienVault OTX"
        if response.status_code == 429:
            return False, "Rate limited"
        if response.status_code >= 400:
            return False, f"HTTP {response.status_code}"
        return True, "Key valid"
