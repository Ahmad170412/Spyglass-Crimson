from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from spyglass.cache import make_key
from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .base import Source

CDX = "https://web.archive.org/cdx/search/cdx"
FIELDS = ("original", "timestamp", "statuscode", "mimetype")


class WaybackSource(Source):
    id = "wayback"
    label = "Historical URLs"
    layer = "core"
    description = "Archived URLs and historical hosts from the Wayback CDX index"
    accepts = ("domain",)
    docs_url = "https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server"

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        if target.kind != "domain" or not target.host:
            raise SourceError("Wayback lookup requires a domain target")
        host = target.host
        cache_key = make_key("wayback", host)
        cached = ctx.cache.get(cache_key)
        if isinstance(cached, dict):
            return _result(self.id, cached)

        limit = max(1, ctx.settings.max_wayback_urls)
        base_params = {
            "url": host,
            "output": "json",
            "collapse": "urlkey",
            "fl": ",".join(FIELDS),
            "limit": limit,
        }
        headers = {"Accept": "application/json, text/plain"}
        scope = "domain"
        primary_error: Exception | None = None
        try:
            payload = ctx.http.get_json(
                CDX,
                params={**base_params, "matchType": "domain"},
                headers=headers,
                timeout=ctx.settings.wayback_timeout,
            )
        except (httpx.HTTPError, ValueError) as exc:
            # The CDX domain scan is slow and the archive is frequently
            # degraded. Fall back to a cheap exact-host lookup so the
            # caller still learns whether the host is archived at all.
            primary_error = exc
            try:
                payload = ctx.http.get_json(
                    CDX,
                    params=base_params,
                    headers=headers,
                    timeout=ctx.settings.wayback_timeout,
                )
            except (httpx.HTTPError, ValueError) as fallback_exc:
                raise SourceError(
                    f"Wayback CDX failed: {exc}; exact-host fallback failed: {fallback_exc}"
                ) from fallback_exc
            scope = "exact_host"

        rows = _rows(payload)
        urls: list[dict[str, Any]] = []
        hosts: set[str] = set()
        first: str | None = None
        last: str | None = None
        for row in rows:
            original = str(row.get("original") or "").strip()
            if not original:
                continue
            timestamp = str(row.get("timestamp") or "").strip()
            status = str(row.get("statuscode") or "").strip()
            mimetype = str(row.get("mimetype") or "").strip()
            try:
                parsed = urlsplit(original)
            except ValueError:
                parsed = None
            if parsed and parsed.hostname:
                hosts.add(parsed.hostname.lower().rstrip("."))
            iso = _iso_timestamp(timestamp)
            if iso:
                first = iso if first is None or iso < first else first
                last = iso if last is None or iso > last else last
            urls.append(
                {
                    "url": original,
                    "timestamp": timestamp or None,
                    "observed_at": iso,
                    "status": status or None,
                    "mime": mimetype or None,
                }
            )

        truncated = len(rows) >= limit
        data = {
            "domain": host,
            "url_count": len(urls),
            "urls": urls,
            "hosts": sorted(hosts),
            "host_count": len(hosts),
            "first_seen": first,
            "last_seen": last,
            "truncated": truncated,
            "scope": scope,
            "source": "Wayback CDX",
        }
        if primary_error is not None:
            data["degraded_reason"] = str(primary_error)
        ctx.cache.set(cache_key, data, ctx.settings.wayback_ttl)
        return _result(self.id, data)


def _rows(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        return []
    if not payload:
        return []
    header = payload[0]
    if not isinstance(header, list):
        return []
    names = [str(item) for item in header]
    output: list[dict[str, Any]] = []
    for row in payload[1:]:
        if isinstance(row, list):
            output.append(
                {
                    names[index]: row[index]
                    for index in range(min(len(names), len(row)))
                }
            )
        elif isinstance(row, dict):
            output.append(row)
    return output


def _iso_timestamp(value: str) -> str | None:
    if len(value) < 14 or not value[:14].isdigit():
        return None
    try:
        return datetime.strptime(value[:14], "%Y%m%d%H%M%S").isoformat() + "Z"
    except ValueError:
        return None


def _result(source: str, data: dict[str, Any]) -> SourceResult:
    count = int(data.get("url_count") or 0)
    degraded = bool(data.get("degraded_reason"))
    return SourceResult(
        source=source,
        status="partial" if degraded else ("ok" if count else "empty"),
        data=data,
        record_count=count,
        truncated=bool(data.get("truncated")),
        provider="Wayback CDX",
    )
