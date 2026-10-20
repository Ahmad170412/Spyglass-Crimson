from __future__ import annotations

import httpx
import respx

from spyglass.sources.dns import DnsSource
from spyglass.validation import parse_website

CF = "https://cloudflare-dns.com/dns-query"
GOOGLE = "https://dns.google/resolve"


def _answers():
    return {
        ("example.com", "A"): [
            {"name": "example.com.", "type": 1, "TTL": 300, "data": "93.184.216.34"}
        ],
        ("example.com", "AAAA"): [
            {"name": "example.com.", "type": 28, "TTL": 300, "data": "2606:2800:220:1:248:1893:25c8:1946"}
        ],
        ("example.com", "NS"): [
            {"name": "example.com.", "type": 2, "TTL": 3600, "data": "a.iana-servers.net."},
            {"name": "example.com.", "type": 2, "TTL": 3600, "data": "b.iana-servers.net."},
        ],
        ("example.com", "MX"): [
            {"name": "example.com.", "type": 15, "TTL": 3600, "data": "10 mail.example.com."}
        ],
        ("example.com", "TXT"): [
            {"name": "example.com.", "type": 16, "TTL": 3600, "data": '"v=spf1 -all"'}
        ],
        ("example.com", "CAA"): [
            {"name": "example.com.", "type": 257, "TTL": 3600, "data": '0 issue "letsencrypt.org"'}
        ],
        ("example.com", "SOA"): [
            {
                "name": "example.com.",
                "type": 6,
                "TTL": 3600,
                "data": "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600",
            }
        ],
        ("_dmarc.example.com", "TXT"): [
            {
                "name": "_dmarc.example.com.",
                "type": 16,
                "TTL": 3600,
                "data": '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"',
            }
        ],
    }


def _handler(answers):
    def handle(request):
        name = request.url.params["name"]
        rtype = request.url.params["type"]
        rows = answers.get((name, rtype), [])
        return httpx.Response(200, json={"Status": 0, "Answer": rows})

    return handle


@respx.mock
def test_dns_normalizes_records(ctx):
    respx.get(CF).mock(side_effect=_handler(_answers()))

    result = DnsSource().run(parse_website("example.com"), ctx)

    assert result.status == "ok"
    assert result.record_count == 9
    assert result.data["resolver"] == "cloudflare"
    assert result.data["records"]["A"] == ["93.184.216.34"]
    assert result.data["records"]["NS"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert result.data["records"]["MX"] == [{"priority": 10, "host": "mail.example.com"}]
    assert result.data["records"]["CAA"] == [
        {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}
    ]
    assert result.data["records"]["SOA"][0]["serial"] == 2024010101
    assert result.data["records"]["SOA"][0]["mname"] == "ns1.example.com"
    assert result.data["spf"] == "v=spf1 -all"
    assert result.data["dmarc"].startswith("v=DMARC1;")
    assert result.data["errors"] == {}


@respx.mock
def test_dns_falls_back_to_google(ctx):
    respx.get(CF).mock(return_value=httpx.Response(503))
    google_answers = {("example.com", "A"): _answers()[("example.com", "A")]}
    respx.get(GOOGLE).mock(side_effect=_handler(google_answers))

    result = DnsSource().run(parse_website("example.com"), ctx)

    assert result.status == "ok"
    assert result.data["resolver"] == "google"
    assert result.data["records"]["A"] == ["93.184.216.34"]


@respx.mock
def test_dns_nxdomain(ctx):
    respx.get(CF).mock(return_value=httpx.Response(200, json={"Status": 3}))

    result = DnsSource().run(parse_website("example.com"), ctx)

    assert result.status == "not_found"
    assert result.record_count == 0
    assert result.data["records"]["A"] == []
