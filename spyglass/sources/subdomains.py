from __future__ import annotations

from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .base import Source
from .ct import CertificateTransparencySource


class SubdomainsSource(Source):
    id = "subdomains"
    label = "Subdomains"
    layer = "core"
    description = "Unique hostnames derived from certificate transparency logs"
    accepts = ("domain",)
    derived_from = ("ct",)
    docs_url = "https://crt.sh/"

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        if target.kind != "domain" or not target.host:
            raise SourceError("Subdomain discovery requires a domain target")
        ct = CertificateTransparencySource().run(target, ctx)
        host = target.host
        names = [
            name
            for name in ct.data.get("hostnames", [])
            if name != host and name.endswith("." + host)
        ]
        names = sorted(set(names))
        return SourceResult(
            source=self.id,
            status="ok" if names else "empty",
            data={
                "domain": host,
                "subdomains": names,
                "count": len(names),
                "derived_from": "ct",
                "provider": ct.provider,
            },
            record_count=len(names),
            truncated=ct.truncated,
            provider=ct.provider,
        )
