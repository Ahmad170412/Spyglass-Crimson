from __future__ import annotations

import httpx
import pytest
import respx

from spyglass.config import Settings
from spyglass.models import SourceError
from spyglass.sources.censys import CensysSource
from spyglass.sources.ipinfo import IpinfoSource
from spyglass.sources.otx import OtxSource
from spyglass.sources.shodan import ShodanSource
from spyglass.sources.urlscan import UrlscanSource
from spyglass.validation import parse_ip_target, parse_website

SHODAN = "https://api.shodan.io"
CENSYS = "https://search.censys.io/api/v2"
IPINFO = "https://ipinfo.io"
OTX = "https://otx.alienvault.com/api/v1"
URLSCAN = "https://urlscan.io/api/v1"


def _give_key(settings: Settings, provider: str, secret: str = "sekret") -> None:
    from spyglass.credentials import CredentialStore

    CredentialStore(settings.credentials_path, use_keyring=False).set(provider, secret)


@respx.mock
def test_shodan_requires_key(ctx, settings):
    with pytest.raises(SourceError, match="No shodan API key"):
        ShodanSource().run(parse_ip_target("1.1.1.1"), ctx)


@respx.mock
def test_shodan_normalizes(ctx, settings):
    _give_key(settings, "shodan")
    respx.get(f"{SHODAN}/shodan/host/1.1.1.1").mock(
        return_value=httpx.Response(
            200,
            json={
                "ip_str": "1.1.1.1",
                "ports": [53, 443, 443],
                "hostnames": ["one.one.one.one"],
                "org": "Cloudflare",
                "os": None,
                "data": [
                    {"port": 53, "transport": "udp", "product": "dnsmasq", "version": "2.80", "data": "DNS"},
                    {"port": 443, "transport": "tcp", "product": "nginx", "version": "", "data": "HTTP"},
                ],
            },
        )
    )

    result = ShodanSource().run(parse_ip_target("1.1.1.1"), ctx)

    assert result.status == "ok"
    assert result.data["ports"] == [53, 443]
    assert result.record_count == 2
    assert result.data["org"] == "Cloudflare"
    assert result.data["services"][0]["port"] == 53


@respx.mock
def test_shodan_rejected_key(ctx, settings):
    _give_key(settings, "shodan")
    respx.get(f"{SHODAN}/shodan/host/1.1.1.1").mock(return_value=httpx.Response(401, json={}))

    with pytest.raises(SourceError, match="rejected the API key"):
        ShodanSource().run(parse_ip_target("1.1.1.1"), ctx)


@respx.mock
def test_censys_ip_and_domain(ctx, settings):
    _give_key(settings, "censys")
    respx.get(f"{CENSYS}/hosts/1.1.1.1").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": {
                    "ip": "1.1.1.1",
                    "autonomous_system": {"asn": 13335, "description": "CLOUDFLARENET"},
                    "location": {"country": "US"},
                    "services": [{"port": 443, "service_name": "HTTP", "transport": "tcp"}],
                }
            },
        )
    )
    respx.get(f"{CENSYS}/hosting/hosts").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": {
                    "hits": [
                        {"ip": "1.1.1.1", "services": [{"port": 80, "service_name": "HTTP"}]},
                        {"ip": "1.0.0.1", "services": [{"port": 443, "service_name": "HTTP"}]},
                    ]
                }
            },
        )
    )

    ip_result = CensysSource().run(parse_ip_target("1.1.1.1"), ctx)
    assert ip_result.data["services"][0]["port"] == 443
    assert ip_result.data["autonomous_system"]["asn"] == 13335

    domain_result = CensysSource().run(parse_website("example.com"), ctx)
    assert domain_result.data["host_count"] == 2
    assert domain_result.record_count == 2


@respx.mock
def test_ipinfo_normalizes(ctx, settings):
    _give_key(settings, "ipinfo")
    respx.get(f"{IPINFO}/1.1.1.1/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "ip": "1.1.1.1",
                "city": "Los Angeles",
                "region": "California",
                "country": "US",
                "loc": "34.05,-118.24",
                "timezone": "America/Los_Angeles",
                "asn": "AS13335",
                "org": "CLOUDFLARENET",
            },
        )
    )

    result = IpinfoSource().run(parse_ip_target("1.1.1.1"), ctx)

    assert result.status == "ok"
    assert result.data["asn"] == "13335"
    assert result.data["country"] == "US"


@respx.mock
def test_otx_passive_dns(ctx, settings):
    _give_key(settings, "otx")
    respx.get(f"{OTX}/indicators/domain/example.com/passive_dns").mock(
        return_value=httpx.Response(
            200,
            json={
                "passive_dns": [
                    {"hostname": "www.example.com", "address": "93.184.216.34", "first": "2020-01-01", "last": "2023-01-01"},
                    {"hostname": "WWW.EXAMPLE.COM.", "address": "93.184.216.35", "first": "2019-01-01", "last": "2024-01-01"},
                    {"hostname": "blog.example.com", "address": "93.184.216.36", "first": "2021-01-01", "last": "2022-01-01"},
                ]
            },
        )
    )

    result = OtxSource().run(parse_website("example.com"), ctx)

    assert result.status == "ok"
    assert result.data["hosts"] == ["blog.example.com", "www.example.com"]
    assert result.data["host_count"] == 2
    assert result.data["first_seen"] == "2019-01-01"
    assert result.data["last_seen"] == "2024-01-01"


@respx.mock
def test_urlscan_normalizes(ctx, settings):
    _give_key(settings, "urlscan")
    respx.get(f"{URLSCAN}/search/").mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 42,
                "results": [
                    {
                        "_id": "abc123",
                        "page": {"url": "https://example.com/", "domain": "example.com", "ip": "93.184.216.34", "status": "200", "server": "ECS", "country": "US", "title": "Example"},
                        "task": {"time": "2024-05-01T00:00:00Z"},
                    }
                ],
            },
        )
    )

    result = UrlscanSource().run(parse_website("example.com"), ctx)

    assert result.status == "ok"
    assert result.data["scan_count"] == 1
    assert result.data["total_available"] == 42
    assert result.data["scans"][0]["uuid"] == "abc123"


@respx.mock
def test_enrichment_cached_after_first_call(ctx, settings):
    _give_key(settings, "ipinfo")
    route = respx.get(f"{IPINFO}/1.1.1.1/json").mock(
        return_value=httpx.Response(200, json={"ip": "1.1.1.1", "country": "US", "asn": "AS13335"})
    )

    first = IpinfoSource().run(parse_ip_target("1.1.1.1"), ctx)
    second = IpinfoSource().run(parse_ip_target("1.1.1.1"), ctx)

    assert route.call_count == 1
    assert second.data == first.data
