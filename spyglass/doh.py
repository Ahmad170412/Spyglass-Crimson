from __future__ import annotations

import json
import re
from typing import Any

import httpx

from .cache import make_key
from .models import SourceContext

CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"
GOOGLE_DOH = "https://dns.google/resolve"

DOH_PROVIDERS = (
    ("cloudflare", CLOUDFLARE_DOH),
    ("google", GOOGLE_DOH),
)


class DohError(Exception):
    pass


def doh_query(
    ctx: SourceContext,
    name: str,
    record_type: str,
    *,
    ttl: int | None = None,
) -> dict[str, Any]:
    """Query Cloudflare DoH, fall back to Google, and cache the raw response."""
    cache_key = make_key("doh", name.lower().rstrip("."), record_type.upper())
    cached = ctx.cache.get(cache_key)
    if cached is not None:
        return cached
    errors: list[str] = []
    for provider, url in DOH_PROVIDERS:
        try:
            response = ctx.http.get(
                url,
                params={"name": name, "type": record_type},
                headers={"Accept": "application/dns-json"},
            )
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"{provider}: {exc}")
            continue
        status = data.get("Status")
        if status not in (0, 3):
            errors.append(f"{provider}: DNS status {status}")
            continue
        data["_provider"] = provider
        ctx.cache.set(cache_key, data, ttl if ttl is not None else ctx.settings.dns_ttl)
        return data
    raise DohError("; ".join(errors) or "DNS lookup failed")


def answer_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = data.get("Answer") or []
    return [row for row in rows if isinstance(row, dict) and "data" in row]


def clean_name(value: str) -> str:
    return value.strip().rstrip(".").lower()


def decode_txt(value: str) -> str:
    """Decode a DoH TXT value, joining multiple quoted character-strings."""
    raw = value.strip()
    if not raw.startswith('"'):
        return raw
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
    if not parts:
        return raw.strip('"')
    decoded: list[str] = []
    for part in parts:
        try:
            decoded.append(json.loads(f'"{part}"'))
        except (ValueError, json.JSONDecodeError):
            decoded.append(part.replace('\\"', '"').replace("\\\\", "\\"))
    return "".join(decoded)
