from __future__ import annotations

import httpx
import respx

from spyglass.sources.asn import AsnSource
from spyglass.validation import parse_ip_target

CF = "https://cloudflare-dns.com/dns-query"
RIPE = "https://stat.ripe.net/data"


@respx.mock
def test_asn_for_ip_uses_team_cymru(ctx):
    respx.get(CF).mock(
        return_value=httpx.Response(
            200,
            json={
                "Status": 0,
                "Answer": [
                    {
                        "name": "61.48.21.104.origin.asn.cymru.com.",
                        "type": 16,
                        "TTL": 3600,
                        "data": '"13335 | 104.16.0.0/13 | US | arin | 2014-03-28"',
                    }
                ],
            },
        )
    )
    respx.get(f"{RIPE}/as-overview/data.json").mock(
        return_value=httpx.Response(200, json={"data": {"holder": "CLOUDFLARENET"}})
    )

    result = AsnSource().run(parse_ip_target("104.21.48.61"), ctx)

    assert result.status == "ok"
    assert result.provider == "Team Cymru"
    assert result.data["asn"] == 13335
    assert result.data["as_name"] == "CLOUDFLARENET"
    assert result.data["prefix"] == "104.16.0.0/13"
    assert result.data["country"] == "US"
    assert result.data["registry"] == "arin"


@respx.mock
def test_asn_for_ip_falls_back_to_ripestat(ctx):
    respx.get(CF).mock(return_value=httpx.Response(200, json={"Status": 0}))
    respx.get(f"{RIPE}/network-info/data.json").mock(
        return_value=httpx.Response(
            200, json={"data": {"asns": ["13335"], "prefix": "104.16.0.0/13"}}
        )
    )
    respx.get(f"{RIPE}/as-overview/data.json").mock(
        return_value=httpx.Response(200, json={"data": {"holder": "CLOUDFLARENET"}})
    )

    result = AsnSource().run(parse_ip_target("104.21.48.61"), ctx)

    assert result.status == "ok"
    assert result.provider == "RIPEstat"
    assert result.data["source"] == "RIPEstat"
    assert result.data["asn"] == 13335
    assert result.data["country"] is None


@respx.mock
def test_asn_target_returns_prefixes(ctx):
    respx.get(f"{RIPE}/as-overview/data.json").mock(
        return_value=httpx.Response(200, json={"data": {"holder": "CLOUDFLARENET"}})
    )
    respx.get(f"{RIPE}/announced-prefixes/data.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "prefixes": [
                        {"prefix": "104.16.0.0/13"},
                        {"prefix": "172.64.0.0/13"},
                        {"prefix": "104.16.0.0/13"},
                    ]
                }
            },
        )
    )

    result = AsnSource().run(parse_ip_target("AS13335"), ctx)

    assert result.status == "ok"
    assert result.data["asn"] == 13335
    assert result.data["as_name"] == "CLOUDFLARENET"
    assert result.data["prefixes"] == ["104.16.0.0/13", "172.64.0.0/13"]
    assert result.data["prefix_count"] == 2
    assert result.record_count == 2


@respx.mock
def test_asn_empty_for_private_address(ctx):
    respx.get(CF).mock(return_value=httpx.Response(200, json={"Status": 3}))
    respx.get(f"{RIPE}/network-info/data.json").mock(
        return_value=httpx.Response(200, json={"data": {"asns": [], "prefix": None}})
    )

    result = AsnSource().run(parse_ip_target("192.168.1.10"), ctx)

    assert result.status == "empty"
    assert result.record_count == 0
