from __future__ import annotations

from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .keyed import KeyedSource

CENSYS = "https://search.censys.io/api/v2"


class CensysSource(KeyedSource):
    id = "censys"
    label = "Censys"
    layer = "enrichment"
    description = "Opt-in host and certificate index lookups with a credit cap"
    accepts = ("ip", "domain")
    requires_key = True
    docs_url = "https://search.censys.io/api"
    key_env = "SPYGLASS_CENSYS_KEY"
    provider = "censys"

    def request_url(self, target: Target) -> str:
        if target.kind == "domain":
            return f"{CENSYS}/hosting/hosts"
        return f"{CENSYS}/hosts/{target.value}"

    def auth_headers(self, key: str) -> dict[str, str]:
        # Censys uses HTTP basic auth with the two credential halves joined.
        return {}

    def fetch(self, target: Target, ctx: SourceContext, key):
        import base64

        # Censys bills per lookup, so the run-level cap is enforced here rather
        # than only documented.
        cap = ctx.settings.max_censys_lookups
        used = ctx.counters.get(self.provider, 0)
        if used >= cap:
            raise SourceError(f"Censys lookup cap reached ({cap} per run)")
        ctx.counters[self.provider] = used + 1

        # Store "id:secret" as one string; encode to a Basic header.
        token = base64.b64encode(key.encode("utf-8")).decode("ascii")
        params = None
        if target.kind == "domain":
            params = {"q": target.value, "per_page": "10"}
        return ctx.http.get(
            self.request_url(target),
            params=params,
            headers={"Authorization": f"Basic {token}"},
            timeout=ctx.settings.http_timeout,
        )

    def normalize(self, target: Target, payload: object) -> SourceResult:
        if not isinstance(payload, dict):
            raise SourceError("Censys returned an unexpected response")
        result = payload.get("result") or {}
        if target.kind == "domain":
            hits = result.get("hits") or []
            services = [
                {
                    "ip": hit.get("ip"),
                    "services": [
                        {"port": s.get("port"), "service_name": s.get("service_name")}
                        for s in (hit.get("services") or [])
                    ],
                }
                for hit in hits
                if isinstance(hit, dict)
            ]
            data = {
                "domain": target.value,
                "hosts": services,
                "host_count": len(services),
                "status": "ok",
                "record_count": len(services),
            }
        else:
            services = [
                {
                    "port": s.get("port"),
                    "service_name": s.get("service_name"),
                    "transport": s.get("transport"),
                }
                for s in (result.get("services") or [])
            ]
            data = {
                "ip": str(result.get("ip") or target.value),
                "autonomous_system": result.get("autonomous_system"),
                "location": result.get("location"),
                "services": services,
                "status": "ok",
                "record_count": len(services),
            }
        return SourceResult(
            source=self.id,
            status="ok",
            data=data,
            record_count=int(data["record_count"]),
            provider=self.label,
        )

    def ttl(self, ctx: SourceContext) -> int:
        return ctx.settings.internetdb_ttl

    def test_key(self, ctx: SourceContext) -> tuple[bool, str]:
        import base64

        key = self.api_key(ctx)
        token = base64.b64encode(key.encode("utf-8")).decode("ascii")
        response = ctx.http.get(
            f"{CENSYS}/meta/account",
            headers={"Authorization": f"Basic {token}"},
            timeout=ctx.settings.http_timeout,
        )
        if response.status_code in {401, 403}:
            return False, "Key rejected by Censys"
        if response.status_code >= 400:
            return False, f"HTTP {response.status_code}"
        return True, "Key valid"
