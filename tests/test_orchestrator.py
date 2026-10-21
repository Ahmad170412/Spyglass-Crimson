from __future__ import annotations

import httpx
import pytest
import respx

from spyglass.db import get_run, list_entities, list_source_runs
from spyglass.orchestrator import (
    build_plan,
    create_run,
    execute_run,
    gate_allows_aggressive,
    record_authorization,
)
from spyglass.validation import parse_ip_target, parse_website

RDAP = "https://rdap.org"
CF = "https://cloudflare-dns.com/dns-query"
INTERNETDB = "https://internetdb.shodan.io"


def _mock_keyless_ip(respx, address: str = "1.1.1.1") -> None:
    respx.get(url__regex=rf"{RDAP}.*").mock(
        return_value=httpx.Response(
            200,
            json={
                "handle": "NET-1-1-1-0-1",
                "name": "LEVEL3",
                "status": ["active"],
                "events": [],
                "entities": [],
            },
        )
    )
    respx.get(url__regex=r"https://stat\.ripe\.net.*").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "asns": [13335],
                    "prefix": "1.1.1.0/24",
                    "country": "US",
                    "registry": "ARIN",
                    "asn_holder": {"name": "CLOUDFLARENET"},
                }
            },
        )
    )
    respx.get(url__regex=r"https://.*dns-query.*").mock(
        return_value=httpx.Response(200, json={"Status": 0, "Answer": [{"name": "x", "type": 12, "TTL": 60, "data": "one.one.one.one."}]})
    )
    respx.get(f"{INTERNETDB}/{address}").mock(
        return_value=httpx.Response(
            200, json={"ip": address, "ports": [53, 443], "hostnames": ["one.one.one.one"], "tags": [], "cpes": [], "vulns": []}
        )
    )
    respx.get("https://check.torproject.org/torbulkexitlist").mock(
        return_value=httpx.Response(200, text="203.0.113.9\n")
    )
    respx.get("https://www.spamhaus.org/drop/drop_v4.json").mock(
        return_value=httpx.Response(200, text='{"cidr":"203.0.113.0/24","sblid":"SBL-TEST","rir":"arin"}\n')
    )
    respx.get("https://www.spamhaus.org/drop/drop_v6.json").mock(
        return_value=httpx.Response(200, text="")
    )


def test_build_plan_orders_derived_last():
    plan = build_plan("domain", None, "passive")
    assert plan[-1] == "subdomains"
    assert "rdap" in plan


def test_build_plan_cidr_uses_ip_sources():
    assert "internetdb" in build_plan("cidr", None, "passive")


def test_build_plan_layer_filter():
    core_only = build_plan("domain", "core", "passive")
    assert all(src in {"rdap", "dns", "ct", "wayback", "subdomains"} for src in core_only)


@respx.mock
def test_execute_run_complete_and_persists(settings):
    _mock_keyless_ip(respx)
    created = create_run(settings, "1.1.1.1")
    result = execute_run(settings, created["id"])

    assert result["status"] == "complete"
    run = get_run(settings.db_path, created["id"])
    assert run["status"] == "complete"
    assert run["finished_at"] is not None

    source_runs = {s["source"]: s for s in list_source_runs(settings.db_path, created["id"])}
    assert source_runs["internetdb"]["status"] == "ok"
    assert source_runs["shodan"]["status"] == "skipped"
    assert source_runs["censys"]["status"] == "skipped"

    kinds = {e["kind"] for e in list_entities(settings.db_path, created["id"])}
    assert "ip" in kinds
    assert "host" in kinds


@respx.mock
def test_keyed_sources_skipped_without_keys(settings):
    _mock_keyless_ip(respx)
    created = create_run(settings, "1.1.1.1")
    result = execute_run(settings, created["id"])

    statuses = {r["source"]: r["status"] for r in result["results"]}
    for keyed in ("shodan", "censys", "ipinfo", "otx"):
        assert statuses[keyed] == "skipped"


@respx.mock
def test_domain_run_derives_subdomains(settings):
    respx.get(url__regex=r"https://rdap\.org.*").mock(
        return_value=httpx.Response(200, json={"handle": "X", "name": "EXAMPLE", "status": ["active"], "events": [], "entities": []})
    )
    respx.get(url__regex=r"https://.*dns-query.*").mock(
        return_value=httpx.Response(
            200,
            json={"Status": 0, "Answer": [{"name": "example.com", "type": 1, "TTL": 60, "data": "93.184.216.34"}]},
        )
    )
    respx.get(url__regex=r"https://crt\.sh.*").mock(
        return_value=httpx.Response(
            200,
            json=[{"common_name": "example.com", "id": 1}, {"common_name": "www.example.com", "id": 2}],
        )
    )
    respx.get(url__regex=r"https://web\.archive\.org.*").mock(return_value=httpx.Response(200, json=[]))

    created = create_run(settings, "example.com", mode="website")
    result = execute_run(settings, created["id"])

    source_runs = {s["source"]: s["status"] for s in result["results"]}
    assert source_runs["subdomains"] == "ok"
    hosts = [e["key"] for e in list_entities(settings.db_path, created["id"], kind="hostname")]
    assert "www.example.com" in hosts


def test_aggressive_gate_requires_authorization(settings):
    assert gate_allows_aggressive(settings, "1.1.1.1") is False

    record_authorization(settings, "1.1.1.1", note="lab range")
    assert gate_allows_aggressive(settings, "1.1.1.1") is True
    assert gate_allows_aggressive(settings, "1.0.0.1") is False


@respx.mock
def test_budget_exhaustion_marks_sources_skipped(settings):
    """A near-zero budget must not error the run: later sources are skipped."""
    _mock_keyless_ip(respx)
    tiny = settings.__class__(
        db_path=settings.db_path,
        instance_path=settings.instance_path,
        credentials_path=settings.credentials_path,
        use_keyring=False,
        http_retries=0,
        run_budget_seconds=0.0,
        source_timeout=5,
    )
    created = create_run(tiny, "1.1.1.1")
    result = execute_run(tiny, created["id"])

    assert result["status"] == "complete"
    statuses = {r["source"]: r.get("status") for r in result["results"]}
    # A zero budget skips every source rather than erroring the run.
    assert statuses
    assert set(statuses.values()) == {"skipped"}
