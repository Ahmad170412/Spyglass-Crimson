from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from .cache import cache_stats
from .config import Settings
from .credentials import CredentialStore, PROVIDERS
from .db import (
    counts,
    db_ok,
    get_run,
    list_entities,
    list_observations,
    list_runs,
    list_source_runs,
    source_health,
    utcnow,
)
from .orchestrator import create_run, gate_allows_aggressive, start_run_in_background
from .sources.registry import META_BY_ID, all_meta, get_source
from .validation import ValidationError, parse_target, parse_website

bp = Blueprint("api", __name__, url_prefix="/api")


def _settings() -> Settings:
    return current_app.extensions["spyglass_settings"]


@bp.after_request
def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/health")
def health():
    settings = _settings()
    healthy = db_ok(settings.db_path)
    payload = {
        "status": "ok" if healthy else "degraded",
        "database": healthy,
        "version": settings.api_version,
        "sources_registered": len(list(all_meta())),
        "counts": counts(settings.db_path) if healthy else {},
        "cache": cache_stats(settings.db_path) if healthy else {"entries": 0, "live": 0},
    }
    return jsonify(payload), (200 if healthy else 503)


@bp.get("/sources")
def sources():
    settings = _settings()
    health_by_source = source_health(settings.db_path)
    items = []
    for meta in all_meta():
        item = meta.public()
        item["health"] = health_by_source.get(
            meta.id,
            {
                "status": "unknown",
                "checked_at": None,
                "latency_ms": None,
                "error": None,
            },
        )
        items.append(item)
    core = [item for item in items if item["layer"] == "core"]
    enrichment = [item for item in items if item["layer"] == "enrichment"]
    return jsonify(
        {
            "sources": items,
            "summary": {
                "core": len(core),
                "core_implemented": sum(1 for item in core if item["implemented"]),
                "enrichment": len(enrichment),
                "enrichment_implemented": sum(
                    1 for item in enrichment if item["implemented"]
                ),
                "keyless": sum(
                    1 for item in items if item["implemented"] and not item["requires_key"]
                ),
            },
        }
    )


@bp.get("/sources/<source_id>")
def source_detail(source_id: str):
    meta = META_BY_ID.get(source_id)
    if meta is None:
        return jsonify({"error": "unknown source"}), 404
    health = source_health(_settings().db_path).get(
        source_id,
        {"status": "unknown", "checked_at": None, "latency_ms": None, "error": None},
    )
    payload = meta.public()
    payload["health"] = health
    return jsonify(payload)


def _settings_obj() -> Settings:
    return _settings()


@bp.post("/runs")
def create_run_endpoint():
    body = request.get_json(silent=True) or {}
    target_value = str(body.get("target") or "").strip()
    mode = str(body.get("mode") or "passive").strip().lower()
    layer = body.get("layer")
    if layer not in (None, "core", "enrichment"):
        return jsonify({"error": "layer must be core, enrichment, or omitted"}), 400

    if not target_value:
        return jsonify({"error": "target is required"}), 400
    if mode not in {"passive", "website"}:
        return jsonify({"error": "mode must be passive or website"}), 400

    settings = _settings_obj()
    try:
        target = parse_website(target_value) if mode == "website" else parse_target(target_value)
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    handle = start_run_in_background(settings, target.value, mode=mode, layer=layer)
    return jsonify(handle), 202


@bp.get("/runs")
def list_runs_endpoint():
    limit = request.args.get("limit", default=50, type=int)
    limit = max(1, min(limit, 200))
    return jsonify({"runs": list_runs(_settings_obj().db_path, limit=limit)})


@bp.get("/runs/<run_id>")
def get_run_endpoint(run_id: str):
    settings = _settings_obj()
    run = get_run(settings.db_path, run_id)
    if run is None:
        return jsonify({"error": "unknown run"}), 404
    run["source_runs"] = list_source_runs(settings.db_path, run_id)
    run["summary"] = _run_summary(run["source_runs"])
    return jsonify(run)


@bp.get("/runs/<run_id>/results")
def run_results(run_id: str):
    settings = _settings_obj()
    run = get_run(settings.db_path, run_id)
    if run is None:
        return jsonify({"error": "unknown run"}), 404
    source_runs = list_source_runs(settings.db_path, run_id)
    return jsonify(
        {
            "run": run,
            "source_runs": source_runs,
            "entities": list_entities(settings.db_path, run_id),
            "observations": list_observations(settings.db_path, run_id),
            "summary": _run_summary(source_runs),
        }
    )


def _run_summary(source_runs: list[dict]) -> dict:
    complete = sum(1 for s in source_runs if s.get("status") in {"ok", "empty", "not_found", "partial"})
    failed = sum(1 for s in source_runs if s.get("status") == "error")
    skipped = sum(1 for s in source_runs if s.get("status") == "skipped")
    return {
        "sources_total": len(source_runs),
        "complete": complete,
        "failed": failed,
        "skipped": skipped,
        "records": sum(int(s.get("record_count") or 0) for s in source_runs),
    }


@bp.get("/credentials")
def credentials_status():
    settings = _settings_obj()
    store = CredentialStore(settings.credentials_path, use_keyring=settings.use_keyring)
    configured = store.configured()
    items = []
    for provider, env_name in PROVIDERS.items():
        meta = META_BY_ID.get(provider)
        items.append(
            {
                "provider": provider,
                "label": meta.label if meta else provider,
                "env": env_name,
                "configured": bool(configured.get(provider)),
                "docs_url": meta.docs_url if meta else "",
            }
        )
    return jsonify({"credentials": items, "backend": store.backend})


@bp.put("/credentials/<provider>")
def set_credential(provider: str):
    settings = _settings_obj()
    if provider not in PROVIDERS:
        return jsonify({"error": "unknown provider"}), 404
    body = request.get_json(silent=True) or {}
    secret = str(body.get("secret") or "").strip()
    if not secret:
        return jsonify({"error": "secret is required"}), 400
    store = CredentialStore(settings.credentials_path, use_keyring=settings.use_keyring)
    store.set(provider, secret)
    return jsonify({"provider": provider, "configured": True})


@bp.delete("/credentials/<provider>")
def delete_credential(provider: str):
    settings = _settings_obj()
    if provider not in PROVIDERS:
        return jsonify({"error": "unknown provider"}), 404
    store = CredentialStore(settings.credentials_path, use_keyring=settings.use_keyring)
    store.delete(provider)
    return jsonify({"provider": provider, "configured": False})


@bp.post("/credentials/<provider>/test")

def test_credential(provider: str):
    settings = _settings_obj()
    if provider not in PROVIDERS:
        return jsonify({"error": "unknown provider"}), 404
    try:
        source = get_source(provider)
    except KeyError:
        return jsonify({"error": "provider has no test adapter"}), 404
    if not hasattr(source, "test_key"):
        return jsonify({"error": "provider cannot be tested"}), 400

    from .services import build_context, close_context

    ctx = build_context(settings)
    try:
        ok, message = source.test_key(ctx)
    except Exception as exc:  # noqa: BLE001 - report the provider failure verbatim
        ok, message = False, str(exc)
    finally:
        close_context(ctx)

    _record_credential_test(settings, provider, ok, message)
    return jsonify({"provider": provider, "ok": ok, "message": message})


def _record_credential_test(settings: Settings, provider: str, ok: bool, message: str) -> None:
    from .db import connect

    with connect(settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO credential_status (provider, configured, last_tested_at, last_error, updated_at)
            VALUES (?, 1, ?, ?, ?)
            ON CONFLICT(provider) DO UPDATE SET
                last_tested_at = excluded.last_tested_at,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at
            """,
            (provider, utcnow(), None if ok else message, utcnow()),
        )
        conn.commit()


@bp.post("/authorizations")

def create_authorization():
    settings = _settings_obj()
    body = request.get_json(silent=True) or {}
    target_value = str(body.get("target") or "").strip()
    if not target_value:
        return jsonify({"error": "target is required"}), 400
    from .orchestrator import record_authorization

    created = record_authorization(settings, target_value, note=body.get("note"))
    return jsonify({"target": target_value, "created_at": created, "scope": "aggressive"}), 201


@bp.get("/authorizations")

def list_authorizations():
    from .db import connect

    settings = _settings_obj()
    with connect(settings.db_path) as conn:
        rows = conn.execute(
            "SELECT id, target, scope, note, created_at, expires_at FROM authorizations ORDER BY id DESC"
        ).fetchall()
    return jsonify({"authorizations": [dict(row) for row in rows]})


@bp.get("/aggressive-gate")
def aggressive_gate():
    settings = _settings_obj()
    target_value = (request.args.get("target") or "").strip()
    allowed = gate_allows_aggressive(settings, target_value) if target_value else False
    return jsonify({"target": target_value, "allowed": allowed})
