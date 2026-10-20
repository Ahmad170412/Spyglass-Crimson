from __future__ import annotations

from spyglass.doh import DohError, answer_rows, clean_name, doh_query
from spyglass.models import SourceContext, SourceError, SourceResult, Target
from spyglass.validation import reverse_pointer

from .base import Source


class PtrSource(Source):
    id = "ptr"
    label = "Reverse DNS"
    layer = "core"
    description = "PTR records for an address through DNS-over-HTTPS"
    accepts = ("ip",)
    docs_url = "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/"

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        if target.kind != "ip" or target.ip is None:
            raise SourceError("Reverse DNS requires a single IP")
        address = str(target.ip)
        try:
            name = reverse_pointer(address)
        except ValueError as exc:
            raise SourceError(str(exc)) from exc
        try:
            data = doh_query(ctx, name, "PTR", ttl=ctx.settings.dns_ttl)
        except DohError as exc:
            raise SourceError(f"Reverse DNS failed: {exc}") from exc
        names = []
        for row in answer_rows(data):
            if row.get("type") not in (None, 12):
                continue
            value = clean_name(str(row.get("data", "")))
            if value and value != name and value not in names:
                names.append(value)
        names.sort()
        payload = {
            "ip": address,
            "ptr": names,
            "count": len(names),
            "resolver": data.get("_provider"),
        }
        return SourceResult(
            source=self.id,
            status="ok" if names else "empty",
            data=payload,
            record_count=len(names),
            provider="DoH",
        )
