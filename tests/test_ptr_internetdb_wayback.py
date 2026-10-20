from __future__ import annotations

import httpx
import pytest
import respx

from spyglass.models import SourceError
from spyglass.sources.internetdb import InternetDbSource
from spyglass.sources.ptr import PtrSource
from spyglass.sources.wayback import WaybackSource
from spyglass.validation import parse_ip_target, parse_website

CF = "https://cloudflare-dns.com/dns-query"
INTERNETDB = "https://internetdb.shodan.io"
CDX = "https://web.archive.org/cdx/search/cdx"


@respx.mock
def test_ptr_lookup(ctx):
    respx.get(CF).mock(
        return_value=httpx.Response(
            200,
            json={
                "Status": 0,
                "Answer": [{"name": "1.1.1.1.in-addr.arpa.", "type": 12, "TTL": 300, "data": "one.one.one.one."}],
            },
        )
    )

    result = PtrSource().run(parse_ip_target("1.1.1.1"), ctx)

    assert result.status == "ok"
    assert result.data["ptr"] == ["one.one.one.one"]
    assert result.record_count == 1


@respx.mock
def test_ptr_empty(ctx):
    respx.get(CF).mock(return_value=httpx.Response(200, json={"Status": 3}))

    result = PtrSource().run(parse_ip_target("192.0.2.1"), ctx)

    assert result.status == "empty"
    assert result.data["ptr"] == []


@respx.mock
def test_internetdb_normalizes_and_caches(ctx):
    route = respx.get(f"{INTERNETDB}/1.1.1.1").mock(
        return_value=httpx.Response(
            200,
            json={
                "ip": "1.1.1.1",
                "ports": [53, 80, 443, 443],
                "hostnames": ["one.one.one.one", "ONE.ONE.ONE.ONE."],
                "tags": ["cdn", "dns"],
                "cpes": ["cpe:/a:cloudflare:cloudflare"],
                "vulns": [],
            },
        )
    )

    target = parse_ip_target("1.1.1.1")
    first = InternetDbSource().run(target, ctx)
    second = InternetDbSource().run(target, ctx)

    assert first.status == "ok"
    assert first.data["ports"] == [53, 80, 443]
    assert first.data["hostnames"] == ["one.one.one.one"]
    assert first.data["tags"] == ["cdn", "dns"]
    assert second.data == first.data
    assert route.call_count == 1


@respx.mock
def test_internetdb_404_is_not_an_error(ctx):
    respx.get(f"{INTERNETDB}/192.0.2.1").mock(
        return_value=httpx.Response(404, json={"detail": "No information available"})
    )

    result = InternetDbSource().run(parse_ip_target("192.0.2.1"), ctx)

    assert result.status == "not_found"
    assert result.record_count == 0
    assert result.data["status"] == "not_found"


@respx.mock
def test_wayback_normalizes_rows(ctx):
    respx.get(CDX).mock(
        return_value=httpx.Response(
            200,
            json=[
                ["original", "timestamp", "statuscode", "mimetype"],
                ["https://example.com/old", "20200101000000", "200", "text/html"],
                ["https://blog.example.com/post", "20220101000000", "301", "text/html"],
                ["https://example.com/old", "20230101000000", "200", "text/html"],
            ],
        )
    )

    result = WaybackSource().run(parse_website("example.com"), ctx)

    assert result.status == "ok"
    assert result.record_count == 3
    assert result.data["hosts"] == ["blog.example.com", "example.com"]
    assert result.data["first_seen"] == "2020-01-01T00:00:00Z"
    assert result.data["last_seen"] == "2023-01-01T00:00:00Z"
    assert result.data["urls"][0]["url"] == "https://example.com/old"


@respx.mock
def test_wayback_empty(ctx):
    respx.get(CDX).mock(return_value=httpx.Response(200, json=[]))

    result = WaybackSource().run(parse_website("example.com"), ctx)

    assert result.status == "empty"
    assert result.record_count == 0


@respx.mock
def test_wayback_falls_back_to_exact_host(ctx):
    respx.get(CDX).mock(
        side_effect=[
            httpx.ReadTimeout("CDX domain scan timed out"),
            httpx.Response(
                200,
                json=[
                    ["original", "timestamp", "statuscode", "mimetype"],
                    ["https://example.com/", "20200601000000", "200", "text/html"],
                ],
            ),
        ]
    )

    result = WaybackSource().run(parse_website("example.com"), ctx)

    assert result.status == "partial"
    assert result.record_count == 1
    assert result.data["scope"] == "exact_host"
    assert "timed out" in result.data["degraded_reason"]


@respx.mock
def test_wayback_raises_when_both_attempts_fail(ctx):
    respx.get(CDX).mock(side_effect=httpx.ReadTimeout("down"))

    with pytest.raises(SourceError, match="exact-host fallback failed"):
        WaybackSource().run(parse_website("example.com"), ctx)
