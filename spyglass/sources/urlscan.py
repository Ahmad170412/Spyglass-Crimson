from __future__ import annotations

from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .keyed import KeyedSource

URLSCAN = "https://urlscan.io/api/v1"


class UrlscanSource(KeyedSource):
    id = "urlscan"
    label = "urlscan.io"
    layer = "enrichment"
    description = "Historical page scans and metadata"
    accepts = ("domain",)
    requires_key = True
    docs_url = "https://urlscan.io/docs/api/"
    key_env = "SPYGLASS_URLSCAN_KEY"
    provider = "urlscan"

    def request_url(self, target: Target) -> str:
        return f"{URLSCAN}/search/"

    def request_params(self, target: Target) -> dict[str, str]:
        return {"q": f"domain:{target.value}", "size": "20"}

    def auth_headers(self, key: str) -> dict[str, str]:
        return {"API-Key": key}

    def fetch(self, target: Target, ctx: SourceContext, key):
        return ctx.http.get(
            self.request_url(target),
            params=self.request_params(target),
            headers=self.auth_headers(key),
            timeout=self.timeout(ctx),
        )

    def timeout(self, ctx: SourceContext):
        return ctx.settings.http_timeout

    def normalize(self, target: Target, payload: object) -> SourceResult:
        if not isinstance(payload, dict):
            raise SourceError("urlscan.io returned an unexpected response")
        results = payload.get("results") or []
        rows = []
        for item in results:
            if not isinstance(item, dict):
                continue
            page = item.get("page") or {}
            task = item.get("task") or {}
            rows.append(
                {
                    "uuid": item.get("_id"),
                    "url": page.get("url") or task.get("url"),
                    "domain": page.get("domain"),
                    "ip": page.get("ip"),
                    "status": page.get("status"),
                    "server": page.get("server"),
                    "country": page.get("country"),
                    "title": page.get("title"),
                    "scanned_at": task.get("time"),
                }
            )
        total = payload.get("total") or len(rows)
        data = {
            "domain": target.value,
            "scans": rows,
            "scan_count": len(rows),
            "total_available": total,
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
            f"{URLSCAN}/user/",
            headers=self.auth_headers(key),
            timeout=ctx.settings.http_timeout,
        )
        if response.status_code in {401, 403}:
            return False, "Key rejected by urlscan.io"
        if response.status_code >= 400:
            return False, f"HTTP {response.status_code}"
        try:
            info = response.json()
        except ValueError:
            return False, "Invalid JSON from urlscan.io"
        if not isinstance(info, dict):
            return False, "Unexpected urlscan.io response"
        quota = info.get("quotas") or {}
        daily = quota.get("day") or {}
        used = daily.get("used")
        limit = daily.get("limit")
        plan = info.get("premium") and "premium" or "free"
        suffix = f" ({used}/{limit} today)" if used is not None and limit else ""
        return True, f"Key valid ({plan} plan){suffix}"
