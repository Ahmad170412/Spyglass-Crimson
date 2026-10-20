from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timezone
from typing import Any

from .cache import Cache
from .config import Settings
from .credentials import CredentialStore
from .db import (
    connect,
    insert_entity,
    insert_observation,
    insert_source_run,
    get_run,
    update_run_status,
)
from .http import HttpClient
from .models import SourceContext, SourceError, Target
from .sources.registry import META_BY_ID, get_source, sources_for
from .validation import expand_network

# Core sources that depend on an earlier source's output. The orchestrator
# runs independent sources first, then fills in dependants with derived data.
DERIVED_SOURCES = {"subdomains"}

ENRICHMENT_PROVIDERS = {
    "shodan": "shodan",
    "censys": "censys",
    "ipinfo": "ipinfo",
    "otx": "otx",
    "urlscan": "urlscan",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]


def gate_allows_aggressive(settings: Settings, target_value: str) -> bool:
    """Server-side check for aggressive modules.

    An aggressive run is allowed only when a recorded authorization exists for
    this exact target and has not expired. The UI toggle is not enforcement.
    """
    from .db import connect as _connect, init_db

    init_db(settings.db_path)
    now = utcnow()
    with _connect(settings.db_path) as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS n FROM authorizations
            WHERE target = ?
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (target_value, now),
        ).fetchone()
    return bool(row and row["n"])


def record_authorization(
    settings: Settings, target_value: str, scope: str = "aggressive", note: str | None = None
) -> str:
    from .db import connect as _connect, init_db, utcnow as _now

    init_db(settings.db_path)
    created = _now()
    with _connect(settings.db_path) as conn:
        conn.execute(
            "INSERT INTO authorizations (target, scope, note, created_at) VALUES (?, ?, ?, ?)",
            (target_value, scope, note, created),
        )
        conn.commit()
    return created


# A CIDR and an ASN are conceptually IP targets: they run the IP source list,
# with the orchestrator sampling addresses for ranges.
PLAN_KIND = {"cidr": "ip", "asn": "ip"}


def build_plan(kind: str, layer: str | None, mode: str) -> list[str]:
    metas = sources_for(PLAN_KIND.get(kind, kind), layer=layer)
    plan = []
    for meta in metas:
        if meta.id in DERIVED_SOURCES:
            continue
        plan.append(meta.id)
    # Run dependants (subdomains) after everything else.
    for meta in metas:
        if meta.id in DERIVED_SOURCES:
            plan.append(meta.id)
    return plan


def _select_ips(target: Target, settings: Settings) -> tuple[list[str], dict[str, Any]]:
    """Return the IP addresses to enrich, plus a note about sampling."""
    if target.kind == "ip":
        return [str(target.ip)], {}
    if target.kind == "cidr":
        expansion = expand_network(target.network, limit=settings.max_ips_per_run)
        note = {
            "sampled": len(expansion.addresses),
            "total": expansion.total,
            "truncated": expansion.truncated,
        }
        return expansion.addresses, note
    return [], {}


def run_sources(
    settings: Settings,
    run_id: str,
    target: Target,
    plan: list[str],
    budget_seconds: float,
) -> list[dict[str, Any]]:
    """Execute the plan, honoring the run budget. Returns source-run records."""
    ctx = SourceContext(
        settings=settings,
        cache=Cache(settings.db_path),
        http=HttpClient(
            timeout=settings.source_timeout,
            user_agent=settings.user_agent,
            retries=0,
        ),
    )
    creds = CredentialStore(
        settings.credentials_path, use_keyring=settings.use_keyring
    )
    configured = creds.configured()
    budget_start = time.monotonic()
    results: list[dict[str, Any]] = []
    derived: dict[str, Any] = {}

    try:
        for source_id in plan:
            elapsed = time.monotonic() - budget_start
            if elapsed >= budget_seconds:
                _record_skipped(settings, run_id, source_id, "run budget exhausted")
                results.append({"source": source_id, "status": "skipped"})
                continue

            meta = META_BY_ID.get(source_id)
            if meta is None:
                continue

            if meta.requires_key and not configured.get(ENRICHMENT_PROVIDERS.get(source_id, source_id)):
                reason = "no API key configured"
                _record_skipped(settings, run_id, source_id, reason)
                results.append({"source": source_id, "status": "skipped", "error": reason})
                continue

            if source_id == "subdomains":
                names = derived.get("hostnames") or []
                _record_subdomains(settings, run_id, names, results)
                continue

            effective_target = target
            if target.kind == "cidr" and source_id in {"asn", "internetdb", "ptr"}:
                ips, note = _select_ips(target, settings)
                if not ips:
                    _record_skipped(settings, run_id, source_id, "no addresses to sample")
                    results.append({"source": source_id, "status": "skipped"})
                    continue
                _run_per_ip(
                    settings, run_id, source_id, ips, note, budget_seconds, budget_start, results
                )
                continue

            if source_id == "censys" and target.kind == "cidr":
                _record_skipped(
                    settings, run_id, source_id, "Censys lookups are capped; not run for a range"
                )
                results.append({"source": source_id, "status": "skipped"})
                continue

            record = _run_single(
                settings, run_id, source_id, effective_target, ctx, budget_seconds, budget_start
            )
            if record is not None:
                results.append(record)
                _harvest(source_id, record, derived)
    finally:
        ctx.http.close()

    return results


def _run_single(
    settings: Settings,
    run_id: str,
    source_id: str,
    target: Target,
    ctx: SourceContext,
    budget_seconds: float,
    budget_start: float,
) -> dict[str, Any] | None:
    source = get_source(source_id)
    remaining = max(1.0, budget_seconds - (time.monotonic() - budget_start))
    started = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(source.run, target, ctx)
            result = future.result(timeout=remaining)
    except FutureTimeout:
        duration_ms = int((time.monotonic() - started) * 1000)
        error = f"{source_id} timed out after {remaining:.0f}s"
        insert_source_run(settings.db_path, run_id, source_id, "error", error=error, duration_ms=duration_ms)
        return {"source": source_id, "status": "error", "error": error, "duration_ms": duration_ms}
    except SourceError as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        insert_source_run(settings.db_path, run_id, source_id, "error", error=str(exc), duration_ms=duration_ms)
        return {"source": source_id, "status": "error", "error": str(exc), "duration_ms": duration_ms}
    except Exception as exc:  # noqa: BLE001 - a single source must never kill the run
        duration_ms = int((time.monotonic() - started) * 1000)
        error = f"{source_id} failed: {exc}"
        insert_source_run(settings.db_path, run_id, source_id, "error", error=error, duration_ms=duration_ms)
        return {"source": source_id, "status": "error", "error": error, "duration_ms": duration_ms}

    duration_ms = int((time.monotonic() - started) * 1000)
    insert_source_run(
        settings.db_path,
        run_id,
        source_id,
        result.status,
        record_count=result.record_count,
        data=result.data,
        duration_ms=duration_ms,
    )
    return {
        "source": source_id,
        "status": result.status,
        "record_count": result.record_count,
        "duration_ms": duration_ms,
        "data": result.data,
    }


def _run_per_ip(
    settings: Settings,
    run_id: str,
    source_id: str,
    ips: list[str],
    note: dict[str, Any],
    budget_seconds: float,
    budget_start: float,
    results: list[dict[str, Any]],
) -> None:
    ctx = SourceContext(
        settings=settings,
        cache=Cache(settings.db_path),
        http=HttpClient(timeout=settings.source_timeout, user_agent=settings.user_agent, retries=0),
    )
    ok = 0
    errors = 0
    collected: list[dict[str, Any]] = []
    try:
        for address in ips:
            if time.monotonic() - budget_start >= budget_seconds:
                break
            ip_target = Target(kind="ip", value=address, raw=address, ip=_ip(address))
            record = _run_single(
                settings, run_id, source_id, ip_target, ctx, budget_seconds, budget_start
            )
            if record is None:
                continue
            if record.get("status") in {"ok", "empty", "not_found", "partial"}:
                ok += 1
                if record.get("data"):
                    collected.append(record["data"])
            else:
                errors += 1
    finally:
        ctx.http.close()

    summary = {
        "source": source_id,
        "status": "ok" if ok else ("error" if errors else "empty"),
        "record_count": ok,
        "ip_count": len(ips),
        "errors": errors,
        "note": note,
        "results": collected,
    }
    results.append(summary)


def _ip(address: str):
    import ipaddress

    return ipaddress.ip_address(address)


def _record_subdomains(
    settings: Settings, run_id: str, hostnames: list[str], results: list[dict[str, Any]]
) -> None:
    if not hostnames:
        insert_source_run(
            settings.db_path, run_id, "subdomains", "empty", record_count=0,
            error="no certificate hostnames to derive from",
        )
        results.append({"source": "subdomains", "status": "empty", "record_count": 0})
        return
    seen: set[str] = set()
    unique = []
    for name in hostnames:
        lowered = str(name).lower().rstrip(".")
        if lowered and lowered not in seen:
            seen.add(lowered)
            unique.append(lowered)
    data = {"subdomains": unique, "count": len(unique), "derived_from": "ct"}
    insert_source_run(
        settings.db_path, run_id, "subdomains", "ok", record_count=len(unique), data=data
    )
    for name in unique:
        insert_entity(settings.db_path, run_id, "hostname", name, {"hostname": name}, "subdomains")
    results.append({"source": "subdomains", "status": "ok", "record_count": len(unique), "data": data})


def _record_skipped(settings: Settings, run_id: str, source_id: str, reason: str) -> None:
    insert_source_run(settings.db_path, run_id, source_id, "skipped", error=reason)


def _harvest(source_id: str, record: dict[str, Any], derived: dict[str, Any]) -> None:
    """Capture cross-source outputs the orchestrator feeds into later steps."""
    data = record.get("data")
    if not isinstance(data, dict):
        return
    if source_id == "ct":
        names = data.get("hostnames") or []
        if names:
            derived["hostnames"] = names
    return


def extract_entities(
    settings: Settings,
    run_id: str,
    target: Target,
    results: list[dict[str, Any]],
) -> None:
    """Persist normalized entities and observations from source results."""
    hosts: set[str] = set()
    ips: set[str] = set()

    if target.kind == "domain" and target.host:
        hosts.add(target.host)
    if target.kind == "ip" and target.ip:
        ips.add(str(target.ip))

    for record in results:
        source_id = record.get("source")
        data = record.get("data")
        if not isinstance(data, dict):
            continue

        if source_id == "dns":
            records = data.get("records") or {}
            for address in records.get("A") or []:
                ips.add(str(address))
            for address in records.get("AAAA") or []:
                ips.add(str(address))
            for record_entry in data.get("records", {}).get("MX") or []:
                host = record_entry.get("host") if isinstance(record_entry, dict) else None
                if host:
                    hosts.add(str(host).lower().rstrip("."))
            insert_entity(
                settings.db_path, run_id, "dns", str(target.value),
                {"records": records, "host": data.get("host")}, source_id,
            )

        elif source_id == "rdap":
            insert_entity(
                settings.db_path, run_id, "registration", str(target.value),
                {k: v for k, v in data.items() if k != "status"}, source_id,
            )

        elif source_id == "ct":
            for cert in data.get("certificates") or []:
                if not isinstance(cert, dict):
                    continue
                name = str(cert.get("name") or cert.get("common_name") or "").lower().rstrip(".")
                if not name:
                    continue
                insert_entity(
                    settings.db_path, run_id, "certificate", name,
                    {k: v for k, v in cert.items() if k != "status"}, source_id,
                )
            for hostname in data.get("hostnames") or []:
                lowered = str(hostname).lower().rstrip(".")
                if lowered:
                    hosts.add(lowered)

        elif source_id == "subdomains":
            for hostname in data.get("subdomains") or []:
                hosts.add(str(hostname).lower().rstrip("."))

        elif source_id == "asn":
            for key in ("asn", "as_name", "prefix", "country", "registry", "allocation"):
                if data.get(key):
                    insert_entity(
                        settings.db_path, run_id, "asn", str(data.get("asn") or target.value),
                        {k: v for k, v in data.items() if k != "status"}, source_id,
                    )
                    break

        elif source_id == "internetdb":
            address = str(data.get("ip") or target.value)
            ips.add(address)
            insert_entity(
                settings.db_path, run_id, "host", address,
                {k: v for k, v in data.items() if k != "status"}, source_id,
            )
            vulns = data.get("vulns") or []
            if vulns:
                insert_observation(
                    settings.db_path, run_id, source=source_id, category="exposure",
                    severity="medium", title=f"{len(vulns)} CVE(s) referenced for {address}",
                    detail=", ".join(str(v) for v in vulns[:20]),
                    data={"vulns": vulns},
                )

        elif source_id in ENRICHMENT_PROVIDERS:
            _harvest_enrichment(settings, run_id, source_id, data)

        elif source_id == "wayback":
            for archived_host in data.get("hosts") or []:
                hosts.add(str(archived_host).lower().rstrip("."))

    for hostname in sorted(hosts):
        insert_entity(settings.db_path, run_id, "hostname", hostname, {"hostname": hostname}, None)
    for address in sorted(ips):
        insert_entity(settings.db_path, run_id, "ip", address, {"ip": address}, None)


def _harvest_enrichment(
    settings: Settings, run_id: str, source_id: str, data: dict[str, Any]
) -> None:
    key = str(data.get("ip") or data.get("domain") or source_id)
    insert_entity(
        settings.db_path, run_id, "enrichment", f"{source_id}:{key}",
        {k: v for k, v in data.items() if k != "status"}, source_id,
    )


def create_run(
    settings: Settings,
    target_value: str,
    mode: str = "passive",
    layer: str | None = None,
    target: Target | None = None,
) -> dict[str, Any]:
    from .validation import parse_target, parse_website

    if target is None:
        target = parse_website(target_value) if mode == "website" else parse_target(target_value)

    from .db import init_db

    init_db(settings.db_path)  # idempotent; keeps first-run and test paths safe
    run_id = new_run_id()
    plan = build_plan(target.kind, layer, mode)
    meta = {
        "plan": plan,
        "layer": layer,
        "requested_mode": mode,
        "budget_seconds": settings.run_budget_seconds,
    }
    insert_row = connect(settings.db_path)
    try:
        insert_row.execute(
            """
            INSERT INTO runs (id, target, target_kind, mode, status, created_at, meta_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, target.value, target.kind, "passive", "queued", utcnow(), _dumps(meta)),
        )
        insert_row.commit()
    finally:
        insert_row.close()

    return {"id": run_id, "target": target.value, "target_kind": target.kind, "plan": plan}


def _dumps(value: Any) -> str:
    import json

    return json.dumps(value, default=str)


def execute_run(settings: Settings, run_id: str) -> dict[str, Any]:
    """Run the plan for an existing run row and persist results."""
    run = get_run(settings.db_path, run_id)
    if run is None:
        raise KeyError(f"Unknown run: {run_id}")

    meta = run.get("meta") or {}
    plan = meta.get("plan") or []
    raw_budget = meta.get("budget_seconds")
    budget = (
        float(raw_budget)
        if raw_budget is not None
        else settings.run_budget_seconds
    )
    kind = run["target_kind"]
    raw_target = run["target"]

    if kind == "domain":
        from .validation import parse_website

        target = parse_website(raw_target)
    else:
        from .validation import parse_target

        target = parse_target(raw_target)

    update_run_status(settings.db_path, run_id, "running", started_at=utcnow())
    try:
        results = run_sources(settings, run_id, target, plan, budget)
        extract_entities(settings, run_id, target, results)
        update_run_status(settings.db_path, run_id, "complete", finished_at=utcnow())
    except Exception as exc:  # noqa: BLE001 - surface orchestration failure on the run
        update_run_status(settings.db_path, run_id, "error", finished_at=utcnow(), error=str(exc))
        raise
    return {"id": run_id, "status": "complete", "results": results}


def start_run_in_background(
    settings: Settings,
    target_value: str,
    mode: str = "passive",
    layer: str | None = None,
) -> dict[str, Any]:
    """Create a run and execute it on a worker thread. Returns the run handle."""
    import threading

    created = create_run(settings, target_value, mode=mode, layer=layer)
    run_id = created["id"]

    def _worker() -> None:
        try:
            execute_run(settings, run_id)
        except Exception:  # noqa: BLE001 - the run row already carries the error
            pass

    thread = threading.Thread(target=_worker, daemon=True, name=f"run-{run_id}")
    thread.start()
    return {"id": run_id, "target": created["target"], "plan": created["plan"], "status": "queued"}
