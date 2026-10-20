from __future__ import annotations

from typing import Any

from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .keyed import KeyedSource

SHODAN = "https://api.shodan.io"


class ShodanSource(KeyedSource):
    id = "shodan"
    label = "Shodan API"
    layer = "enrichment"
    description = "Banner and service detail; InternetDB remains the keyless default"
    accepts = ("ip",)
    requires_key = True
    docs_url = "https://developer.shodan.io/api"
    key_env = "SPYGLASS_SHODAN_KEY"
    provider = "shodan"

    def request_url(self, target: Target) -> str:
        return f"{SHODAN}/shodan/host/{target.value}"

    def request_params(self, target: Target) -> dict[str, str] | None:
        return None

    def auth_headers(self, key: str) -> dict[str, str]:
        # Shodan reads the key from the query string, not a header.
        return {}

    def fetch(self, target: Target, ctx: SourceContext, key: str):
        return ctx.http.get(
            self.request_url(target),
            params={"key": key},
            timeout=self.timeout(ctx),
        )

    def normalize(self, target: Target, payload: object) -> SourceResult:
        if not isinstance(payload, dict):
            raise SourceError("Shodan returned an unexpected response")
        services = []
        for item in payload.get("data") or []:
            if not isinstance(item, dict):
                continue
            services.append(
                {
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "banner": (item.get("data") or "").strip()[:400],
                }
            )
        data = {
            "ip": str(payload.get("ip_str") or target.value),
            "ports": sorted(
                {int(p) for p in payload.get("ports") or [] if str(p).isdigit()}
            ),
            "hostnames": sorted(
                {str(h).lower() for h in payload.get("hostnames") or [] if h}
            ),
            "os": payload.get("os"),
            "org": payload.get("org"),
            "isp": payload.get("isp"),
            "asn": payload.get("asn"),
            "country": payload.get("country_code"),
            "city": payload.get("city"),
            "last_update": payload.get("last_update"),
            "services": services,
            "status": "ok",
            "record_count": len(services),
        }
        return SourceResult(
            source=self.id,
            status="ok" if services else "empty",
            data=data,
            record_count=len(services),
            provider=self.label,
        )

    def ttl(self, ctx: SourceContext) -> int:
        return ctx.settings.internetdb_ttl

    def test_key(self, ctx: SourceContext) -> tuple[bool, str]:
        key = self.api_key(ctx)
        response = ctx.http.get(
            f"{SHODAN}/api-info", params={"key": key}, timeout=ctx.settings.http_timeout
        )
        if response.status_code == 401:
            return False, "Key rejected by Shodan"
        if response.status_code >= 400:
            return False, f"HTTP {response.status_code}"
        try:
            info = response.json()
        except ValueError:
            return False, "Invalid JSON from Shodan"
        if not isinstance(info, dict):
            return False, "Unexpected Shodan response"
        plan = info.get("plan") or "free"
        return True, f"Key valid ({plan} plan)"
