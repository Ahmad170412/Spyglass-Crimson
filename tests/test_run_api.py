from __future__ import annotations

import httpx
import pytest

import spyglass.orchestrator as orch
from spyglass.orchestrator import create_run, execute_run

IANA_V4 = "https://data.iana.org/rdap/ipv4.json"
CF = "https://cloudflare-dns.com/dns-query"
INTERNETDB = "https://internetdb.shodan.io"

V4_BOOTSTRAP = {"services": [[["1.1.0.0/16"], ["https://rdap.example.net/"]]]}
RDAP_NET = {
    "handle": "NET-1-1-1-0-1",
    "name": "LEVEL3",
    "status": ["active"],
    "events": [],
    "entities": [],
}


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=None)


class FakeHttpClient:
    """Thread-safe stand-in for HttpClient so the orchestrator's worker
    thread never escapes the mock and reaches the real network."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, *, params=None, headers=None, timeout=None, **_extra):
        # Adapters pass cache/ttl/cache_key straight through to get_json.
        self.calls.append(url)
        for prefix, payload in self.routes:
            if url.startswith(prefix):
                return FakeResponse(payload)
        raise AssertionError(f"Unexpected URL in test: {url}")

    def get_json(self, url, **kwargs):
        return self.get(url, **kwargs).json()

    def get_text(self, url, **kwargs):
        return str(self.get(url, **kwargs).json())

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


def keyless_ip_routes(address="1.1.1.1"):
    return [
        (IANA_V4, V4_BOOTSTRAP),
        ("https://rdap.example.net/ip/", RDAP_NET),
        ("https://stat.ripe.net/data/network-info/", {"data": {"asns": ["13335"], "prefix": "1.1.1.0/24"}}),
        ("https://stat.ripe.net/data/as-overview/", {"data": {"holder": "CLOUDFLARENET, US"}}),
        ("https://stat.ripe.net/data/announced-prefixes/", {"data": {"prefixes": [{"prefix": "1.1.1.0/24"}]}}),
        (CF, {"Status": 0, "Answer": [{"name": "1.1.1.1.in-addr.arpa.", "type": 12, "TTL": 300, "data": "one.one.one.one."}]}),
        (f"{INTERNETDB}/{address}", {"ip": address, "ports": [53], "hostnames": [], "tags": [], "cpes": [], "vulns": []}),
        ("https://check.torproject.org/torbulkexitlist", "203.0.113.9\n"),
        ("https://www.spamhaus.org/drop/drop_v4.json", '{"cidr":"203.0.113.0/24","sblid":"SBL-TEST","rir":"arin"}\n'),
        ("https://www.spamhaus.org/drop/drop_v6.json", ""),
    ]


@pytest.fixture
def fake_http(monkeypatch):
    created = []

    def _install(routes):
        client = FakeHttpClient(routes)
        created.append(client)
        monkeypatch.setattr(orch, "HttpClient", lambda **_kw: client)
        return client

    yield _install
    assert created, "fake_http fixture was not used"


def test_list_runs_empty(api):
    response = api.get("/api/runs")
    assert response.status_code == 200
    assert response.get_json()["runs"] == []


def test_run_endpoints_round_trip(api, settings, fake_http):
    fake_http(keyless_ip_routes())
    created = create_run(settings, "1.1.1.1")
    run_id = created["id"]

    listed = api.get("/api/runs").get_json()["runs"]
    assert [r["id"] for r in listed] == [run_id]
    assert listed[0]["status"] == "queued"

    execute_run(settings, run_id)

    detail = api.get(f"/api/runs/{run_id}")
    assert detail.status_code == 200
    payload = detail.get_json()
    assert payload["status"] == "complete"
    assert payload["summary"]["sources_total"] == 10
    assert payload["summary"]["failed"] == 0
    sources = {s["source"]: s["status"] for s in payload["source_runs"]}
    assert sources["internetdb"] == "ok"
    assert sources["rdap"] == "ok"
    assert sources["shodan"] == "skipped"

    results = api.get(f"/api/runs/{run_id}/results").get_json()
    kinds = {e["kind"] for e in results["entities"]}
    assert "ip" in kinds
    assert results["summary"]["records"] >= 1


def test_run_not_found(api):
    assert api.get("/api/runs/deadbeef0000").status_code == 404
    assert api.get("/api/runs/deadbeef0000/results").status_code == 404


def test_credentials_endpoints_never_leak_secrets(api):
    listed = api.get("/api/credentials").get_json()
    assert listed["backend"] == "file"
    assert len(listed["credentials"]) == 5
    for item in listed["credentials"]:
        assert "secret" not in str(item).lower()

    saved = api.put("/api/credentials/ipinfo", json={"secret": "tok-123"})
    assert saved.status_code == 200

    status = api.get("/api/credentials").get_json()
    configured = {c["provider"]: c["configured"] for c in status["credentials"]}
    assert configured["ipinfo"] is True
    assert "tok-123" not in str(status)

    deleted = api.delete("/api/credentials/ipinfo")
    assert deleted.get_json()["configured"] is False


def test_credentials_validation(api):
    assert api.put("/api/credentials/nope", json={"secret": "x"}).status_code == 404
    assert api.put("/api/credentials/ipinfo", json={}).status_code == 400
    assert api.put("/api/credentials/ipinfo", json={"secret": "   "}).status_code == 400


def test_credential_test_endpoint(api, monkeypatch):
    calls = []

    class _OkSource:
        def test_key(self, ctx):
            calls.append(ctx)
            return True, "Key valid (free plan)"

    monkeypatch.setattr(
        "spyglass.api.get_source", lambda provider: _OkSource()
    )
    api.put("/api/credentials/ipinfo", json={"secret": "good-token"})

    response = api.post("/api/credentials/ipinfo/test")
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["provider"] == "ipinfo"
    assert len(calls) == 1
    assert "good-token" not in response.get_data(as_text=True)


def test_credential_test_reports_rejection(api, monkeypatch):
    class _BadSource:
        def test_key(self, ctx):
            return False, "Token rejected by IPinfo"

    monkeypatch.setattr("spyglass.api.get_source", lambda provider: _BadSource())
    api.put("/api/credentials/ipinfo", json={"secret": "bad-token"})

    payload = api.post("/api/credentials/ipinfo/test").get_json()
    assert payload["ok"] is False
    assert "rejected" in payload["message"].lower()


def test_credential_test_unknown_provider(api):
    assert api.post("/api/credentials/nope/test").status_code == 404


def test_aggressive_gate_endpoints(api, settings):
    closed = api.get("/api/aggressive-gate?target=1.1.1.1").get_json()
    assert closed["allowed"] is False

    created = api.post("/api/authorizations", json={"target": "1.1.1.1", "note": "lab"})
    assert created.status_code == 201

    opened = api.get("/api/aggressive-gate?target=1.1.1.1").get_json()
    assert opened["allowed"] is True

    other = api.get("/api/aggressive-gate?target=1.0.0.1").get_json()
    assert other["allowed"] is False

    listed = api.get("/api/authorizations").get_json()["authorizations"]
    assert listed[0]["target"] == "1.1.1.1"
    assert "secret" not in str(listed).lower()


def test_credentials_status_never_returns_key_values(api, settings):
    from spyglass.credentials import CredentialStore

    CredentialStore(settings.credentials_path, use_keyring=False).set("shodan", "super-secret-key")

    payload = api.get("/api/credentials").get_json()
    assert "super-secret-key" not in str(payload)
    for item in payload["credentials"]:
        assert set(item) == {"provider", "label", "env", "configured", "docs_url"}
