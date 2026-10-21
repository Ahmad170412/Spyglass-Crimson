from __future__ import annotations

import httpx
import pytest
import respx

from spyglass.db import (
    connect,
    get_run,
    list_entities,
    list_observations,
    list_source_runs,
)
from spyglass.models import SourceError
from spyglass.orchestrator import create_run, execute_run, record_authorization
from spyglass.sources.http_probe import MAX_BODY_BYTES, HttpProbeSource
from spyglass.validation import parse_ip_target, parse_website

PUBLIC = [(2, 1, 6, "", ("93.184.216.34", 0))]


@pytest.fixture
def public_dns(monkeypatch):
    monkeypatch.setattr(
        "spyglass.sources._active.socket.getaddrinfo",
        lambda *_args, **_kwargs: PUBLIC,
    )


@respx.mock
def test_probe_requires_authorization(ctx):
    with pytest.raises(SourceError, match="authorization"):
        HttpProbeSource().run(parse_website("example.com"), ctx)


@respx.mock
def test_probe_normalizes_response(ctx, settings, public_dns):
    record_authorization(settings, "example.com")
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            html="<html><head><title>  Example   Domain </title></head></html>",
            headers={
                "server": "nginx",
                "strict-transport-security": "max-age=31536000",
            },
        )
    )
    result = HttpProbeSource().run(parse_website("example.com"), ctx)
    assert result.status == "ok"
    assert result.data["status_code"] == 200
    assert result.data["server"] == "nginx"
    assert result.data["title"] == "Example Domain"
    assert "x-frame-options" in result.data["missing_security_headers"]
    assert "strict-transport-security" not in result.data["missing_security_headers"]


@respx.mock
def test_probe_does_not_follow_redirects(ctx, settings, public_dns):
    record_authorization(settings, "example.com")
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(301, headers={"location": "https://elsewhere.example/"})
    )
    result = HttpProbeSource().run(parse_website("example.com"), ctx)
    assert result.data["status_code"] == 301
    assert result.data["redirect"] == "https://elsewhere.example/"
    assert result.data["title"] is None


@respx.mock
def test_probe_truncates_large_body(ctx, settings, public_dns):
    record_authorization(settings, "example.com")
    body = "<title>big</title>" + ("a" * (MAX_BODY_BYTES * 2))
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, html=body))
    result = HttpProbeSource().run(parse_website("example.com"), ctx)
    assert result.data["body_truncated"] is True
    assert result.data["body_bytes"] == MAX_BODY_BYTES


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.1.2.3", "100.64.0.1", "169.254.1.1", "0.0.0.0", "::1"],
)
def test_probe_refuses_non_public_addresses(ctx, settings, monkeypatch, address):
    record_authorization(settings, "example.com")
    if ":" in address:
        answer = [(10, 1, 6, "", (address, 0, 0, 0))]
    else:
        answer = [(2, 1, 6, "", (address, 0))]
    monkeypatch.setattr(
        "spyglass.sources._active.socket.getaddrinfo",
        lambda *_args, **_kwargs: answer,
    )
    with pytest.raises(SourceError, match="non-public"):
        HttpProbeSource().run(parse_website("example.com"), ctx)


def test_probe_refuses_when_authorization_is_for_another_target(ctx, settings, public_dns):
    record_authorization(settings, "other.example")
    with pytest.raises(SourceError, match="authorization"):
        HttpProbeSource().run(parse_website("example.com"), ctx)


@respx.mock
def test_probe_accepts_an_ip_target(ctx, settings, public_dns):
    record_authorization(settings, "93.184.216.34")
    respx.get("https://93.184.216.34/").mock(
        return_value=httpx.Response(200, html="<title>ip</title>")
    )
    result = HttpProbeSource().run(parse_ip_target("93.184.216.34"), ctx)
    assert result.data["host"] == "93.184.216.34"
    assert result.data["title"] == "ip"


@respx.mock
def test_aggressive_run_sends_one_request_and_records_surface(ctx, settings, public_dns):
    record_authorization(settings, "example.com")
    created = create_run(
        settings, "example.com", mode="website", layer="aggressive", aggressive=True
    )
    assert created["plan"][0] == "http"
    assert set(created["plan"]) == {"http", "nmap", "nuclei"}

    route = respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            html="<title>ok</title>",
            headers={"x-frame-options": "DENY"},
        )
    )
    execute_run(settings, created["id"])

    assert route.call_count == 1
    assert get_run(settings.db_path, created["id"])["status"] == "complete"
    rows = list_source_runs(settings.db_path, created["id"])
    by_source = {row["source"]: row for row in rows}
    assert by_source["http"]["status"] == "ok"

    entities = list_entities(settings.db_path, created["id"])
    assert any(item["key"] == "http:example.com" for item in entities)
    observations = list_observations(settings.db_path, created["id"])
    assert observations and observations[0]["category"] == "surface"


def test_expired_authorization_blocks_the_probe_at_execution(settings):
    record_authorization(settings, "example.com")
    created = create_run(
        settings, "example.com", mode="website", layer="aggressive", aggressive=True
    )
    assert created["plan"][0] == "http"
    assert set(created["plan"]) == {"http", "nmap", "nuclei"}

    with connect(settings.db_path) as conn:
        conn.execute(
            "UPDATE authorizations SET expires_at = '2000-01-01T00:00:00+00:00'"
        )
        conn.commit()

    execute_run(settings, created["id"])

    rows = list_source_runs(settings.db_path, created["id"])
    by_source = {row["source"]: row for row in rows}
    assert by_source["http"]["status"] == "skipped"
    assert "authorization" in by_source["http"]["error"]
    assert by_source["nmap"]["status"] == "skipped"
    assert by_source["nuclei"]["status"] == "skipped"
