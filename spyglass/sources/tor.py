from __future__ import annotations

from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .base import Source

TOR_EXIT_LIST = "https://check.torproject.org/torbulkexitlist"
CACHE_KEY = "dataset:tor-exits"


class TorExitSource(Source):
    """Is this address a current Tor exit node?

    Uses the Tor Project's authoritative bulk exit list: one small text file,
    refreshed roughly hourly. Matching is local, so an address in the list is
    never sent to the Tor Project.
    """

    id = "tor"
    label = "Tor exits"
    layer = "core"
    description = "Whether an IPv4 address is a current Tor exit node"
    accepts = ("ip",)
    docs_url = "https://www.torproject.org/"

    def exit_addresses(self, ctx: SourceContext) -> set[str]:
        cached = ctx.cache.get(CACHE_KEY)
        if isinstance(cached, list) and cached:
            return {str(item) for item in cached}
        try:
            body = ctx.http.get_text(TOR_EXIT_LIST)
        except Exception as exc:  # noqa: BLE001 - any transport failure is a source failure
            raise SourceError(f"Tor exit list unavailable: {exc}") from exc
        addresses = {
            line.strip()
            for line in body.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        if not addresses:
            raise SourceError("Tor exit list was empty")
        ctx.cache.set(CACHE_KEY, sorted(addresses), ctx.settings.tor_ttl)
        return addresses

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        if target.kind != "ip" or target.ip is None:
            raise SourceError("Tor exit checks require a single IP")
        address = target.ip
        if address.version == 6:
            # The authoritative bulk list only publishes IPv4 exits; claiming
            # "not an exit" for IPv6 would be a false negative.
            return SourceResult(
                source=self.id,
                status="partial",
                data={
                    "ip": str(address),
                    "is_tor_exit": False,
                    "dataset": "tor-bulk-exitlist",
                    "note": "The Tor bulk exit list is IPv4-only; IPv6 exit status is unknown.",
                },
                record_count=0,
                provider="Tor Project",
            )
        exits = self.exit_addresses(ctx)
        listed = str(address) in exits
        payload = {
            "ip": str(address),
            "is_tor_exit": listed,
            "list_size": len(exits),
            "dataset": "tor-bulk-exitlist",
        }
        return SourceResult(
            source=self.id,
            status="ok" if listed else "empty",
            data=payload,
            record_count=1 if listed else 0,
            provider="Tor Project",
        )
