from __future__ import annotations

from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .keyed import KeyedSource

IPINFO = "https://ipinfo.io"


class IpinfoSource(KeyedSource):
    id = "ipinfo"
    label = "IPinfo Lite"
    layer = "enrichment"
    description = "ASN, country, and continent enrichment"
    accepts = ("ip",)
    requires_key = True
    docs_url = "https://ipinfo.io/developers"
    key_env = "SPYGLASS_IPINFO_TOKEN"
    provider = "ipinfo"

    def request_url(self, target: Target) -> str:
        return f"{IPINFO}/{target.value}/json"

    def auth_params(self, key: str) -> dict[str, str]:
        return {"token": key}

    def fetch(self, target: Target, ctx: SourceContext, key):
        return ctx.http.get(
            self.request_url(target),
            params=self.auth_params(key),
            timeout=ctx.settings.http_timeout,
        )

    def normalize(self, target: Target, payload: object) -> SourceResult:
        if not isinstance(payload, dict):
            raise SourceError("IPinfo returned an unexpected response")
        if payload.get("bogon") is True:
            data = {
                "ip": str(payload.get("ip") or target.value),
                "bogon": True,
                "status": "ok",
                "record_count": 0,
            }
            return SourceResult(
                source=self.id,
                status="ok",
                data=data,
                record_count=0,
                provider=self.label,
            )
        asn = str(payload.get("asn") or "")
        data = {
            "ip": str(payload.get("ip") or target.value),
            "hostname": payload.get("hostname"),
            "city": payload.get("city"),
            "region": payload.get("region"),
            "country": payload.get("country"),
            "loc": payload.get("loc"),
            "postal": payload.get("postal"),
            "timezone": payload.get("timezone"),
            "asn": asn.lstrip("AS") or None,
            "org": payload.get("org"),
            "status": "ok",
            "record_count": 1,
        }
        return SourceResult(
            source=self.id,
            status="ok",
            data=data,
            record_count=1,
            provider=self.label,
        )

    def ttl(self, ctx: SourceContext) -> int:
        return ctx.settings.routing_ttl

    def test_key(self, ctx: SourceContext) -> tuple[bool, str]:
        key = self.api_key(ctx)
        response = ctx.http.get(
            f"{IPINFO}/1.1.1.1/json",
            params=self.auth_params(key),
            timeout=ctx.settings.http_timeout,
        )
        if response.status_code in {401, 403}:
            return False, "Token rejected by IPinfo"
        if response.status_code == 429:
            return False, "Rate limited"
        if response.status_code >= 400:
            return False, f"HTTP {response.status_code}"
        return True, "Token valid"
