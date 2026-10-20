from __future__ import annotations

import httpx
import respx

from spyglass.sources.rdap import RdapSource, _parse_whois_domain
from spyglass.validation import parse_ip_target, parse_website

BOOTSTRAP = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["org"], ["https://rdap.publicinterestregistry.org/rdap/"]],
    ]
}

DOMAIN = {
    "ldhName": "EXAMPLE.COM",
    "handle": "2336799_DOMAIN_COM-VRSN",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2025-08-14T07:01:38Z"},
    ],
    "entities": [
        {
            "handle": "376",
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]],
            "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
        },
        {
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "abuse@example.com"]]],
        },
    ],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
    "secureDNS": {"delegationSigned": True},
}


@respx.mock
def test_rdap_domain(ctx):
    respx.get("https://data.iana.org/rdap/dns.json").mock(
        return_value=httpx.Response(200, json=BOOTSTRAP)
    )
    respx.get("https://rdap.verisign.com/com/v1/domain/example.com").mock(
        return_value=httpx.Response(200, json=DOMAIN)
    )

    result = RdapSource().run(parse_website("example.com"), ctx)

    assert result.status == "ok"
    assert result.provider == "RDAP"
    assert result.data["name"] == "example.com"
    assert result.data["registrar"]["name"] == "RESERVED-Internet Assigned Numbers Authority"
    assert result.data["registrar"]["iana_id"] == "376"
    assert result.data["abuse_email"] == "abuse@example.com"
    assert result.data["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert result.data["events"]["registered"] == "1995-08-14T04:00:00Z"
    assert result.data["dnssec"] is True


@respx.mock
def test_rdap_domain_falls_back_to_rdap_org(ctx):
    respx.get("https://data.iana.org/rdap/dns.json").mock(
        return_value=httpx.Response(200, json={"services": []})
    )
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json=DOMAIN)
    )

    result = RdapSource().run(parse_website("example.com"), ctx)

    assert result.provider == "rdap.org"
    assert result.data["provider"] == "rdap.org"


@respx.mock
def test_rdap_ip_selects_longest_bootstrap_prefix(ctx):
    respx.get("https://data.iana.org/rdap/ipv4.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "services": [
                    [["104.16.0.0/12"], ["https://rdap.broad.example/"]],
                    [["104.21.0.0/16"], ["https://rdap.narrow.example/"]],
                ]
            },
        )
    )
    respx.get("https://rdap.narrow.example/ip/104.21.48.61").mock(
        return_value=httpx.Response(
            200,
            json={
                "handle": "NET-104-21-0-0-1",
                "name": "CLOUDFLARENET",
                "startAddress": "104.21.0.0",
                "endAddress": "104.21.255.255",
                "type": "DIRECT ALLOCATION",
                "country": "US",
                "parentHandle": "NET-104-16-0-0-1",
                "events": [{"eventAction": "registration", "eventDate": "2017-04-05T00:00:00Z"}],
                "entities": [
                    {
                        "roles": ["registrant"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]],
                    },
                    {
                        "roles": ["abuse"],
                        "vcardArray": ["vcard", [["email", {}, "text", "abuse@cloudflare.com"]]],
                    },
                ],
            },
        )
    )

    result = RdapSource().run(parse_ip_target("104.21.48.61"), ctx)

    assert result.status == "ok"
    assert result.data["name"] == "CLOUDFLARENET"
    assert result.data["cidrs"] == ["104.21.0.0/16"]
    assert result.data["organization"]["name"] == "Cloudflare, Inc."
    assert result.data["abuse_email"] == "abuse@cloudflare.com"
    assert result.data["events"]["registered"] == "2017-04-05T00:00:00Z"


def test_whois_domain_parser():
    text = """
% comment
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2026-08-13T04:00:00Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Domain Status: clientTransferProhibited
DNSSEC: unsigned
"""
    data = _parse_whois_domain("example.com", text)
    assert data["registrar"]["name"] == "Example Registrar, Inc."
    assert data["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert data["dnssec"] is False
    assert data["events"]["expires"] == "2026-08-13T04:00:00Z"
