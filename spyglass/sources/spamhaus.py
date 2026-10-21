from __future__ import annotations

import ipaddress
import json

from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .base import Source

DROP_V4 = "https://www.spamhaus.org/drop/drop_v4.json"
DROP_V6 = "https://www.spamhaus.org/drop/drop_v6.json"
CACHE_KEY = "dataset:spamhaus-drop"


def _parse_jsonl(body: str) -> list[list[str]]:
    """Spamhaus publishes DROP as JSON Lines, one netblock per line."""
    rows: list[list[str]] = []
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        cidr = item.get("cidr")
        if not cidr:
            continue
        rows.append([str(cidr), str(item.get("sblid") or ""), str(item.get("rir") or "")])
    return rows


class SpamhausDropSource(Source):
    """Checks an address against the Spamhaus DROP "do not route or peer" list.

    DROP covers hijacked and bulletproof-hosting netblocks. The dataset is a
    small JSON-lines file published once a day; matching happens locally.
    """

    id = "spamhaus"
    label = "Spamhaus DROP"
    layer = "core"
    description = "Hijacked and bulletproof-hosting netblocks from Spamhaus DROP"
    accepts = ("ip",)
    docs_url = "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"

    def dataset(self, ctx: SourceContext) -> tuple[list[list[str]], list[str]]:
        cached = ctx.cache.get(CACHE_KEY)
        if isinstance(cached, dict) and cached.get("rows"):
            return list(cached["rows"]), list(cached.get("degraded") or [])
        rows: list[list[str]] = []
        degraded: list[str] = []
        for url in (DROP_V4, DROP_V6):
            try:
                rows.extend(_parse_jsonl(ctx.http.get_text(url)))
            except Exception:  # noqa: BLE001 - one family failing still yields a partial answer
                degraded.append(url.rsplit("/", 1)[-1])
        if not rows:
            raise SourceError("Spamhaus DROP dataset unavailable")
        payload = {"rows": rows, "degraded": degraded}
        # Retry a partial dataset within the hour instead of trusting it all day.
        ttl = ctx.settings.drop_ttl if not degraded else min(ctx.settings.drop_ttl, 3600)
        ctx.cache.set(CACHE_KEY, payload, ttl)
        return rows, degraded

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        if target.kind != "ip" or target.ip is None:
            raise SourceError("Spamhaus DROP checks require a single IP")
        address = target.ip
        rows, degraded = self.dataset(ctx)

        matches: list[dict[str, str]] = []
        for cidr, sblid, rir in rows:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if network.version != address.version:
                continue
            if address in network:
                matches.append({"cidr": cidr, "sblid": sblid, "rir": rir})

        listed = bool(matches)
        if listed:
            status = "ok"
        elif degraded:
            status = "partial"
        else:
            status = "empty"

        payload = {
            "ip": str(address),
            "listed": listed,
            "matches": matches,
            "dataset_size": len(rows),
            "degraded": degraded,
        }
        return SourceResult(
            source=self.id,
            status=status,
            data=payload,
            record_count=len(matches),
            provider="Spamhaus",
        )
