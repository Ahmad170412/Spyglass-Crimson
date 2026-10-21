from __future__ import annotations

import subprocess
from dataclasses import replace

import pytest

from spyglass.db import list_entities, list_observations
from spyglass.models import SourceError
from spyglass.orchestrator import create_run, extract_entities, record_authorization
from spyglass.sources import registry
from spyglass.sources.nmap import NmapSource
from spyglass.sources.nuclei import NucleiSource
from spyglass.validation import ValidationError, parse_ip_target, parse_website

PUBLIC = [(2, 1, 6, "", ("93.184.216.34", 0))]
ADDRESS = "93.184.216.34"

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NUCLEI_JSONL = "\n".join(
    [
        '{"template-id":"tech-detect","info":{"name":"Technology Detection",'
        '"severity":"info","tags":["tech"]},"matched-at":"https://93.184.216.34/",'
        '"type":"http"}',
        '{"template-id":"missing-csp","info":{"name":"Missing CSP Header",'
        '"severity":"low","tags":["headers"]},"matched-at":"https://93.184.216.34/",'
        '"type":"http"}',
        "not json at all",
    ]
)


@pytest.fixture
def public_dns(monkeypatch):
    monkeypatch.setattr(
        "spyglass.sources._active.socket.getaddrinfo",
        lambda *_args, **_kwargs: PUBLIC,
    )


@pytest.fixture
def fake_run(monkeypatch):
    calls = []

    def _run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, NMAP_XML, "")

    monkeypatch.setattr("spyglass.sources.nmap.subprocess.run", _run)
    return calls


@pytest.fixture
def fake_nuclei(monkeypatch):
    calls = []

    def _run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, NUCLEI_JSONL, "")

    monkeypatch.setattr("spyglass.sources.nuclei.subprocess.run", _run)
    return calls


def test_nmap_requires_authorization(ctx):
    with pytest.raises(SourceError, match="authorization"):
        NmapSource().run(parse_ip_target(ADDRESS), ctx)


def test_nmap_requires_binary(ctx, settings, monkeypatch):
    record_authorization(settings, ADDRESS)
    monkeypatch.setattr("spyglass.sources._active.shutil.which", lambda _name: None)
    with pytest.raises(SourceError, match="not installed"):
        NmapSource().run(parse_ip_target(ADDRESS), ctx)


def test_nmap_refuses_non_public_targets(ctx, settings):
    record_authorization(settings, "127.0.0.1")
    with pytest.raises(SourceError, match="non-public"):
        NmapSource().run(parse_ip_target("127.0.0.1"), ctx)


def test_nmap_command_is_bounded(ctx, settings, fake_run):
    record_authorization(settings, ADDRESS)
    result = NmapSource().run(parse_ip_target(ADDRESS), ctx)

    assert result.status == "ok"
    assert result.record_count == 2
    assert [port["port"] for port in result.data["open_ports"]] == [22, 443]
    assert result.data["open_ports"][0]["product"] == "OpenSSH"

    command, kwargs = fake_run[0]
    assert kwargs["shell"] is False
    assert command[1:5] == ["-Pn", "-n", "-sT", "-T3"]
    assert "--top-ports" in command
    assert command[command.index("--top-ports") + 1] == "100"
    assert command[-1] == ADDRESS
    # No OS detection, no NSE scripts, no UDP, no host discovery tricks.
    joined = " ".join(command)
    for forbidden in ("-O", "-sU", "-sS", "--script", "-A"):
        assert forbidden not in joined.split()


def test_nmap_empty_scan_is_not_an_error(ctx, settings, monkeypatch):
    record_authorization(settings, ADDRESS)
    empty = NMAP_XML.replace('state="open"', 'state="closed"')
    monkeypatch.setattr(
        "spyglass.sources.nmap.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, empty, ""),
    )
    result = NmapSource().run(parse_ip_target(ADDRESS), ctx)
    assert result.status == "empty"
    assert result.record_count == 0


def test_nmap_reports_failure(ctx, settings, monkeypatch):
    record_authorization(settings, ADDRESS)
    monkeypatch.setattr(
        "spyglass.sources.nmap.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 1, "", "Failed to resolve name"
        ),
    )
    with pytest.raises(SourceError, match="nmap failed"):
        NmapSource().run(parse_ip_target(ADDRESS), ctx)


def test_nmap_resolves_a_domain_target(ctx, settings, public_dns, fake_run):
    record_authorization(settings, "example.com")
    result = NmapSource().run(parse_website("example.com"), ctx)
    assert result.data["ip"] == ADDRESS
    assert fake_run[0][0][-1] == ADDRESS


def test_nuclei_requires_authorization(ctx):
    with pytest.raises(SourceError, match="authorization"):
        NucleiSource().run(parse_website("example.com"), ctx)


def test_nuclei_requires_binary(ctx, settings, public_dns, monkeypatch):
    record_authorization(settings, "example.com")
    monkeypatch.setattr("spyglass.sources._active.shutil.which", lambda _name: None)
    with pytest.raises(SourceError, match="not installed"):
        NucleiSource().run(parse_website("example.com"), ctx)


def test_nuclei_parses_jsonl_and_caps_findings(ctx, settings, public_dns, fake_nuclei):
    record_authorization(settings, "example.com")
    result = NucleiSource().run(parse_website("example.com"), ctx)

    assert result.status == "ok"
    assert result.record_count == 2
    assert result.data["truncated"] is False
    assert [item["severity"] for item in result.data["findings"]] == ["info", "low"]

    command, kwargs = fake_nuclei[0]
    assert kwargs["shell"] is False
    assert "-jsonl" in command
    assert "-no-interactsh" in command
    assert "-disable-redirects" in command
    assert "-sT" not in command
    assert command[command.index("-etags") + 1] == (
        "dos,fuzz,intrusive,brute-force,default-login"
    )
    assert command[command.index("-rate-limit") + 1] == "20"


def test_nuclei_truncates_at_the_configured_cap(
    ctx, settings, public_dns, fake_nuclei
):
    record_authorization(settings, "example.com")
    capped = replace(settings, max_nuclei_findings=1)
    ctx = replace(ctx, settings=capped)
    result = NucleiSource().run(parse_website("example.com"), ctx)
    assert result.record_count == 1
    assert result.data["truncated"] is True


def test_nuclei_empty_output(ctx, settings, public_dns, monkeypatch):
    record_authorization(settings, "example.com")
    monkeypatch.setattr(
        "spyglass.sources.nuclei.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )
    result = NucleiSource().run(parse_website("example.com"), ctx)
    assert result.status == "empty"


def test_registry_marks_scanner_requirements():
    assert registry.META_BY_ID["nmap"].requires_binary == "nmap"
    assert registry.META_BY_ID["nuclei"].requires_binary == "nuclei"
    assert registry.META_BY_ID["nmap"].layer == "aggressive"
    assert registry.META_BY_ID["nuclei"].layer == "aggressive"
    passive = {item.id for item in registry.sources_for("domain")}
    assert not {"nmap", "nuclei", "http"} & passive
    opted_in = {item.id for item in registry.sources_for("domain", include_aggressive=True)}
    assert {"nmap", "nuclei", "http"} <= opted_in


def test_sources_endpoint_reports_missing_binaries(api, monkeypatch):
    monkeypatch.setattr("spyglass.api.shutil.which", lambda _name: None)
    payload = api.get("/api/sources").get_json()
    by_id = {item["id"]: item for item in payload["sources"]}
    assert by_id["nmap"]["available"] is False
    assert by_id["nmap"]["missing"] == "nmap"
    assert by_id["nuclei"]["available"] is False
    assert by_id["http"]["available"] is True
    assert payload["summary"]["aggressive_available"] == 1


def test_active_sources_narrows_the_plan(settings):
    record_authorization(settings, ADDRESS)
    created = create_run(
        settings, ADDRESS, aggressive=True, active_sources=["nmap"]
    )
    assert set(created["plan"]) & {"http", "nmap", "nuclei"} == {"nmap"}

    with pytest.raises(ValidationError, match="requires aggressive"):
        create_run(settings, ADDRESS, active_sources=["nmap"])
    with pytest.raises(ValidationError, match="not an active module"):
        create_run(settings, ADDRESS, aggressive=True, active_sources=["rdap"])
    with pytest.raises(ValidationError, match="must not be empty"):
        create_run(settings, ADDRESS, aggressive=True, active_sources=[])


def test_active_sources_api_validation(api):
    response = api.post(
        "/api/runs",
        json={"target": ADDRESS, "aggressive": False, "active_sources": ["nmap"]},
    )
    assert response.status_code == 400
    assert "requires aggressive" in response.get_json()["error"]

    response = api.post(
        "/api/runs",
        json={"target": ADDRESS, "aggressive": True, "active_sources": ["rdap"]},
    )
    assert response.status_code == 400
    assert "unknown active module" in response.get_json()["error"]

    response = api.post(
        "/api/runs",
        json={"target": ADDRESS, "aggressive": True, "active_sources": []},
    )
    assert response.status_code == 400


def test_aggressive_runs_never_touch_ranges(settings):
    from spyglass.orchestrator import build_plan

    plan = build_plan("cidr", None, "passive", include_aggressive=True)
    assert not {"http", "nmap", "nuclei"} & set(plan)
    plan = build_plan("asn", None, "passive", include_aggressive=True)
    assert not {"http", "nmap", "nuclei"} & set(plan)

    record_authorization(settings, "8.8.8.0/24")
    with pytest.raises(ValidationError, match="single host"):
        create_run(settings, "8.8.8.0/24", aggressive=True)


def test_active_results_become_entities_and_observations(settings):
    created = create_run(settings, ADDRESS)
    results = [
        {
            "source": "nmap",
            "status": "ok",
            "data": {
                "ip": ADDRESS,
                "host": None,
                "host_up": True,
                "open_ports": [
                    {"port": 22, "protocol": "tcp", "service": "ssh"},
                    {"port": 443, "protocol": "tcp", "service": "https"},
                ],
                "ports_scanned": 100,
            },
            "record_count": 2,
        },
        {
            "source": "nuclei",
            "status": "ok",
            "data": {
                "host": ADDRESS,
                "url": f"https://{ADDRESS}/",
                "findings": [
                    {
                        "template": "missing-csp",
                        "name": "Missing CSP Header",
                        "severity": "low",
                        "matched_at": f"https://{ADDRESS}/",
                        "type": "http",
                        "tags": ["headers"],
                    }
                ],
                "truncated": False,
            },
            "record_count": 1,
        },
    ]
    extract_entities(settings, created["id"], parse_ip_target(ADDRESS), results)

    observations = list_observations(settings.db_path, created["id"])
    by_category = {item["category"]: item for item in observations}
    assert by_category["exposure"]["severity"] == "medium"
    assert "2 open TCP port" in by_category["exposure"]["title"]
    assert by_category["vulnerability"]["severity"] == "low"
    assert by_category["vulnerability"]["title"] == (
        f"Missing CSP Header on {ADDRESS}"
    )

    entities = list_entities(settings.db_path, created["id"])
    keys = {item["key"] for item in entities}
    assert ADDRESS in keys
    assert f"nuclei:{ADDRESS}" in keys
