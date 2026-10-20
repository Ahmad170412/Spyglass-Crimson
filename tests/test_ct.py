from __future__ import annotations

import httpx
import respx

from spyglass.sources.ct import CertificateTransparencySource
from spyglass.sources.subdomains import SubdomainsSource
from spyglass.validation import parse_website

CRT = "https://crt.sh/"
SPOTTER = "https://api.certspotter.com/v1/issuances"

CRT_ROWS = [
    {
        "id": 101,
        "name_value": "example.com\nwww.example.com\n*.example.com",
        "common_name": "example.com",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
        "not_before": "2024-01-01T00:00:00",
        "not_after": "2024-04-01T00:00:00",
    },
    {
        "id": 102,
        "name_value": "api.example.com\nwww.example.com",
        "common_name": "api.example.com",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R10",
        "not_before": "2024-02-01T00:00:00",
        "not_after": "2024-05-01T00:00:00",
    },
]


@respx.mock
def test_ct_normalizes_and_deduplicates(ctx):
    respx.get(CRT).mock(return_value=httpx.Response(200, json=CRT_ROWS))

    result = CertificateTransparencySource().run(parse_website("example.com"), ctx)

    assert result.status == "ok"
    assert result.provider == "crt.sh"
    assert result.record_count == 2
    assert result.data["hostnames"] == ["api.example.com", "example.com", "www.example.com"]
    assert result.data["wildcards"] == ["example.com"]
    assert result.data["certificate_count"] == 2
    assert result.data["hostname_count"] == 3
    assert result.data["certificates"][0]["issuer"].startswith("C=US")


@respx.mock
def test_subdomains_uses_ct_cache(ctx):
    route = respx.get(CRT).mock(return_value=httpx.Response(200, json=CRT_ROWS))

    target = parse_website("example.com")
    CertificateTransparencySource().run(target, ctx)
    result = SubdomainsSource().run(target, ctx)

    assert result.status == "ok"
    assert result.data["subdomains"] == ["api.example.com", "www.example.com"]
    assert result.data["count"] == 2
    assert route.call_count == 1


@respx.mock
def test_ct_falls_back_to_certspotter(ctx):
    respx.get(CRT).mock(return_value=httpx.Response(502, text="bad gateway"))
    respx.get(SPOTTER).mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": "abc123",
                    "dns_names": ["example.com", "dev.example.com"],
                    "issuer": {"name": "ISRG Root X1"},
                    "not_before": "2024-03-01T00:00:00Z",
                    "not_after": "2024-06-01T00:00:00Z",
                }
            ],
        )
    )

    result = CertificateTransparencySource().run(parse_website("example.com"), ctx)

    assert result.status == "partial"
    assert result.provider == "Cert Spotter"
    assert result.data["hostnames"] == ["dev.example.com", "example.com"]
    assert "crt.sh" in result.errors
    assert "crt.sh" in result.data["errors"][0]


@respx.mock
def test_ct_truncates_names(ctx, settings):
    import dataclasses
    from spyglass.cache import Cache
    from spyglass.http import HttpClient
    from spyglass.models import SourceContext

    limited = dataclasses.replace(settings, max_ct_names=1)
    client = HttpClient(timeout=5, user_agent="test", retries=0)
    local = SourceContext(settings=limited, cache=Cache(limited.db_path), http=client)
    try:
        respx.get(CRT).mock(return_value=httpx.Response(200, json=CRT_ROWS))
        result = CertificateTransparencySource().run(parse_website("example.com"), local)
        assert result.data["hostname_count"] == 1
        assert result.truncated is True
    finally:
        client.close()
