from __future__ import annotations

import threading
import time
from dataclasses import replace

import pytest

from spyglass.db import (
    connect,
    init_db,
    insert_entity,
    insert_run,
    list_entities,
    list_source_runs,
    source_health,
)
from spyglass.models import SourceContext, SourceError, SourceResult
from spyglass.orchestrator import (
    build_plan,
    create_run,
    execute_run,
    gate_allows_aggressive,
    record_authorization,
    run_sources,
)
from spyglass.sources.base import Source
from spyglass.sources.censys import CensysSource
from spyglass.sources.registry import ADAPTERS, META_BY_ID, SourceMeta
from spyglass.validation import ValidationError, parse_ip_target, parse_website


class _Stub(Source):
    def __init__(self, source_id: str, status: str = "ok", data: dict | None = None):
        self.id = source_id
        self.label = source_id
        self.accepts = ("domain", "ip")
        self._status = status
        self._data = data or {}

    def __call__(self):
        return self

    def run(self, target, ctx):
        return SourceResult(
            source=self.id, status=self._status, record_count=1, data=self._data
        )


# --- Host header ------------------------------------------------------


def test_foreign_host_header_is_rejected(api):
    assert api.get("/", headers={"Host": "evil.example"}).status_code == 400
    assert api.get("/api/health", headers={"Host": "evil.example"}).status_code == 400


def test_loopback_host_headers_are_allowed(api):
    assert api.get("/", headers={"Host": "localhost"}).status_code == 200
    assert api.get("/api/health", headers={"Host": "127.0.0.1:5000"}).status_code == 200


# --- Authorization ----------------------------------------------------


def test_authorization_expires(settings):
    record_authorization(settings, "1.1.1.1", ttl_days=1)
    assert gate_allows_aggressive(settings, "1.1.1.1") is True

    with connect(settings.db_path) as conn:
        conn.execute(
            "UPDATE authorizations SET expires_at = '2000-01-01T00:00:00+00:00'"
        )
        conn.commit()

    assert gate_allows_aggressive(settings, "1.1.1.1") is False


def test_authorization_rejects_non_positive_ttl(settings):
    with pytest.raises(ValueError):
        record_authorization(settings, "1.1.1.1", ttl_days=0)


def test_authorization_without_expiry_is_not_honoured(settings):
    init_db(settings.db_path)
    with connect(settings.db_path) as conn:
        conn.execute(
            "INSERT INTO authorizations (target, scope, created_at) VALUES (?, ?, ?)",
            ("1.1.1.1", "aggressive", "2020-01-01T00:00:00+00:00"),
        )
        conn.commit()
    assert gate_allows_aggressive(settings, "1.1.1.1") is False


def test_authorization_normalises_urls(api, settings):
    response = api.post(
        "/api/authorizations",
        json={"target": "https://example.com/path?q=1", "ttl_days": 7},
    )
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["target"] == "example.com"
    assert payload["expires_at"] > payload["created_at"]
    assert gate_allows_aggressive(settings, "example.com") is True


# --- Budget -----------------------------------------------------------


def test_budget_bounds_a_hanging_source(settings, monkeypatch):
    """A source that hangs must not stretch the run past its budget."""
    release = threading.Event()

    class Hanging(Source):
        def run(self, target, ctx):
            release.wait(2.0)
            return SourceResult(source="slow", status="ok", record_count=1, data={})

    monkeypatch.setitem(ADAPTERS, "slow", Hanging)
    monkeypatch.setitem(
        META_BY_ID,
        "slow",
        SourceMeta(id="slow", label="Slow", layer="core", description="", accepts=("domain",)),
    )
    init_db(settings.db_path)
    insert_run(settings.db_path, "probe", "example.com", "domain", "passive")

    started = time.monotonic()
    try:
        results = run_sources(
            settings, "probe", parse_website("example.com"), ["slow"], 0.2
        )
    finally:
        release.set()
    elapsed = time.monotonic() - started

    assert elapsed < 1.0
    assert results[0]["status"] == "error"
    assert "timed out" in results[0]["error"]


# --- Source health ----------------------------------------------------


def test_run_records_source_health(settings, monkeypatch):
    monkeypatch.setitem(ADAPTERS, "dns", _Stub("dns", data={"records": {}}))
    created = create_run(
        settings, "example.com", mode="website", layer="core", sources=["dns"]
    )
    execute_run(settings, created["id"])

    health = source_health(settings.db_path)
    assert health["dns"]["status"] == "ok"
    assert health["dns"]["latency_ms"] is not None


def test_source_health_is_surfaced_by_the_api(api, settings, monkeypatch):
    monkeypatch.setitem(ADAPTERS, "dns", _Stub("dns", data={"records": {}}))
    created = create_run(
        settings, "example.com", mode="website", layer="core", sources=["dns"]
    )
    execute_run(settings, created["id"])

    payload = api.get("/api/sources").get_json()
    by_id = {item["id"]: item for item in payload["sources"]}
    assert by_id["dns"]["health"]["status"] == "ok"


# --- Entity provenance ------------------------------------------------


def test_entity_provenance_is_not_overwritten(settings):
    init_db(settings.db_path)
    insert_run(settings.db_path, "r1", "example.com", "domain", "passive")
    insert_entity(settings.db_path, "r1", "hostname", "www.example.com", {}, "subdomains")
    insert_entity(settings.db_path, "r1", "hostname", "www.example.com", {}, None)

    rows = list_entities(settings.db_path, "r1")
    assert rows[0]["source"] == "subdomains"


# --- Plan selection ---------------------------------------------------


def test_build_plan_narrows_to_selected_sources():
    plan = build_plan("domain", None, "website", ["rdap"])
    assert "rdap" in plan
    assert "dns" not in plan
    assert "censys" in plan, "enrichment providers stay planned so they can report a skip reason"
    assert plan[-1] == "subdomains", "derived sources still run last"


def test_build_plan_excludes_aggressive_by_default():
    assert "http" not in build_plan("domain", None, "website")
    assert "http" in build_plan("domain", None, "website", include_aggressive=True)


def test_build_plan_keeps_aggressive_when_sources_are_selected():
    plan = build_plan("domain", None, "website", ["rdap"], include_aggressive=True)
    assert "http" in plan
    assert "rdap" in plan
    assert "dns" not in plan


def test_run_endpoint_forwards_selected_sources(api, monkeypatch):
    captured: dict = {}

    def fake(settings, target, **kwargs):
        captured.update(kwargs)
        captured["target"] = target
        return {"id": "abc", "target": target, "plan": ["rdap"], "status": "queued"}

    monkeypatch.setattr("spyglass.api.start_run_in_background", fake)
    response = api.post(
        "/api/runs",
        json={"target": "example.com", "mode": "website", "sources": ["rdap"]},
    )
    assert response.status_code == 202
    assert captured["sources"] == ["rdap"]


def test_run_endpoint_rejects_unknown_source(api):
    response = api.post(
        "/api/runs",
        json={"target": "example.com", "mode": "website", "sources": ["nope"]},
    )
    assert response.status_code == 400


def test_run_endpoint_rejects_aggressive_source_as_a_tool(api):
    response = api.post(
        "/api/runs",
        json={"target": "example.com", "mode": "website", "sources": ["http"]},
    )
    assert response.status_code == 400


def test_aggressive_run_requires_authorization(api):
    response = api.post(
        "/api/runs",
        json={"target": "example.com", "mode": "website", "aggressive": True},
    )
    assert response.status_code == 403
    assert "authorization" in response.get_json()["error"]


def test_create_run_rejects_aggressive_without_authorization(settings):
    with pytest.raises(PermissionError):
        create_run(settings, "example.com", mode="website", aggressive=True)


def test_aggressive_run_accepted_once_authorized(api, monkeypatch):
    api.post("/api/authorizations", json={"target": "example.com"})
    monkeypatch.setattr(
        "spyglass.api.start_run_in_background",
        lambda *args, **kwargs: {
            "id": "abc",
            "target": "example.com",
            "plan": ["http"],
            "status": "queued",
        },
    )
    response = api.post(
        "/api/runs",
        json={"target": "example.com", "mode": "website", "aggressive": True},
    )
    assert response.status_code == 202


# --- CIDR handling ----------------------------------------------------


def test_oversized_cidr_is_rejected(settings):
    with pytest.raises(ValidationError):
        create_run(settings, "10.0.0.0/8")


def test_cidr_run_records_one_row_per_source(settings, monkeypatch):
    monkeypatch.setitem(
        ADAPTERS, "asn", _Stub("asn", data={"asn": "AS64500", "as_name": "TEST"})
    )
    created = create_run(settings, "192.0.2.0/30", layer="core", sources=["asn"])
    execute_run(settings, created["id"])

    rows = [
        row
        for row in list_source_runs(settings.db_path, created["id"])
        if row["source"] == "asn"
    ]
    assert len(rows) == 1
    assert rows[0]["data"]["sampled"] == 2

    # Aggregation must not lose per-address entities.
    entities = list_entities(settings.db_path, created["id"])
    assert any(item["kind"] == "asn" for item in entities)


# --- Censys cap -------------------------------------------------------


def test_censys_lookup_cap_is_enforced(settings, cache, http):
    capped = replace(settings, max_censys_lookups=0)
    ctx = SourceContext(settings=capped, cache=cache, http=http)
    with pytest.raises(SourceError, match="cap"):
        CensysSource().fetch(parse_ip_target("1.1.1.1"), ctx, "id:secret")
