from __future__ import annotations

import json
import os

import pytest

from spyglass.credentials import CredentialStore
from spyglass.db import record_source_health


def test_cache_round_trip_and_ttl(cache, monkeypatch):
    cache.set("sample", {"ok": True}, ttl=10)
    assert cache.get("sample") == {"ok": True}
    assert cache.purge_expired() == 0

    monkeypatch.setattr("spyglass.cache.time.time", lambda: 10**12)
    assert cache.get("sample") is None


def test_credential_file_fallback(tmp_path, monkeypatch):
    path = tmp_path / "credentials.json"
    store = CredentialStore(path, use_keyring=False)
    store.set("shodan", "local-secret")
    assert store.get("shodan") == "local-secret"
    assert store.configured()["shodan"] is True
    assert store.backend == "file"
    # The credential file must not be readable by anyone but the owner. Only
    # POSIX exposes that as mode bits: Windows has no POSIX permission model
    # and os.stat() synthesizes 0o666 for any writable file there, so the
    # check is meaningful exactly where the mode bits are real. On Windows the
    # file sits under the user profile and is governed by NTFS ACLs.
    if os.name == "posix":
        assert oct(path.stat().st_mode & 0o777) == "0o600"
    else:
        assert path.is_file()
    assert "local-secret" not in json.dumps(store.public_status())

    monkeypatch.setenv("SPYGLASS_SHODAN_KEY", "env-secret")
    assert store.get("shodan") == "env-secret"

    store.delete("shodan")
    assert store.get("shodan") == "env-secret"
    monkeypatch.delenv("SPYGLASS_SHODAN_KEY")
    assert store.get("shodan") is None

    with pytest.raises(ValueError):
        store.set("unknown", "x")


def test_api_health_and_sources(api, settings, monkeypatch):
    monkeypatch.setattr("spyglass.api.shutil.which", lambda name: f"/usr/bin/{name}")
    response = api.get("/api/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["database"] is True
    assert payload["sources_registered"] == 18
    assert payload["cache"] == {"entries": 0, "live": 0}

    response = api.get("/api/sources")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["summary"] == {
        "core": 10,
        "core_implemented": 10,
        "enrichment": 5,
        "enrichment_implemented": 5,
        "aggressive": 3,
        "aggressive_implemented": 3,
        "aggressive_available": 3,
        "keyless": 10,
    }
    by_id = {item["id"]: item for item in payload["sources"]}
    assert by_id["internetdb"]["implemented"] is True
    assert by_id["internetdb"]["requires_key"] is False
    assert by_id["shodan"]["implemented"] is True
    assert by_id["shodan"]["requires_key"] is True
    # Keyed sources must still be reported as enrichment-layer, not core.
    assert by_id["shodan"]["layer"] == "enrichment"
    assert by_id["rdap"]["health"]["status"] == "unknown"
    assert "spyglass_shodan_key" not in json.dumps(payload).lower()
    assert "secret" not in json.dumps(payload).lower()

    record_source_health(settings.db_path, "rdap", "ok", latency_ms=42)
    payload = api.get("/api/sources").get_json()
    by_id = {item["id"]: item for item in payload["sources"]}
    assert by_id["rdap"]["health"]["status"] == "ok"
    assert by_id["rdap"]["health"]["latency_ms"] == 42

    assert api.get("/api/sources/nope").status_code == 404
    assert api.get("/api/sources/rdap").get_json()["id"] == "rdap"


def test_index_view_still_serves(api):
    response = api.get("/")
    assert response.status_code == 200
    assert b"Spyglass-Crimson" in response.data
    assert api.get("/static/css/app.css").status_code == 200


def test_api_no_store(api):
    response = api.get("/api/health")
    assert response.headers["Cache-Control"] == "no-store"
