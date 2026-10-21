from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('passive', 'aggressive')),
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    meta_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS source_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    duration_ms INTEGER,
    record_count INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    data_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_source_runs_run ON source_runs(run_id);

CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    data_json TEXT NOT NULL,
    source TEXT,
    UNIQUE(run_id, kind, key)
);
CREATE INDEX IF NOT EXISTS idx_entities_run_kind ON entities(run_id, kind);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    source TEXT,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    data_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_observations_run ON observations(run_id);

CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at REAL NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache(expires_at);

CREATE TABLE IF NOT EXISTS credential_status (
    provider TEXT PRIMARY KEY,
    configured INTEGER NOT NULL DEFAULT 0,
    last_tested_at TEXT,
    last_error TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_health (
    source TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    latency_ms INTEGER,
    error TEXT
);

CREATE TABLE IF NOT EXISTS authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scope TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_authorizations_target ON authorizations(target);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db(db_path: str | Path) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT OR IGNORE INTO schema_meta (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
        conn.commit()
    # Run history is investigation data. Keep it owner-only on POSIX hosts.
    try:
        Path(db_path).chmod(0o600)
    except OSError:
        pass


def db_ok(db_path: str | Path) -> bool:
    try:
        with connect(db_path) as conn:
            conn.execute("SELECT 1").fetchone()
        return True
    except sqlite3.Error:
        return False


def record_source_health(
    db_path: str | Path,
    source: str,
    status: str,
    *,
    latency_ms: int | None = None,
    error: str | None = None,
    checked_at: str | None = None,
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO source_health (source, status, checked_at, latency_ms, error)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET
                status = excluded.status,
                checked_at = excluded.checked_at,
                latency_ms = excluded.latency_ms,
                error = excluded.error
            """,
            (source, status, checked_at or utcnow(), latency_ms, error),
        )
        conn.commit()


def source_health(db_path: str | Path) -> dict[str, dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM source_health").fetchall()
    return {
        row["source"]: {
            "status": row["status"],
            "checked_at": row["checked_at"],
            "latency_ms": row["latency_ms"],
            "error": row["error"],
        }
        for row in rows
    }


def counts(db_path: str | Path) -> dict[str, int]:
    with connect(db_path) as conn:
        result = {}
        for table in ("runs", "source_runs", "entities", "observations", "authorizations"):
            result[table] = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
    return result


def insert_run(
    db_path: str | Path,
    run_id: str,
    target: str,
    target_kind: str,
    mode: str,
    status: str = "queued",
    meta: dict[str, Any] | None = None,
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO runs (id, target, target_kind, mode, status, created_at, meta_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, target, target_kind, mode, status, utcnow(), json.dumps(meta or {})),
        )
        conn.commit()


def insert_source_run(
    db_path: str | Path,
    run_id: str,
    source: str,
    status: str,
    *,
    record_count: int = 0,
    error: str | None = None,
    data: Any | None = None,
    duration_ms: int | None = None,
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO source_runs
                (run_id, source, status, started_at, finished_at, duration_ms, record_count, error, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                source,
                status,
                utcnow(),
                utcnow(),
                duration_ms,
                record_count,
                error,
                json.dumps(data) if data is not None else None,
            ),
        )
        conn.commit()


def insert_many(db_path: str | Path, sql: str, rows: Iterable[tuple[Any, ...]]) -> None:
    with connect(db_path) as conn:
        conn.executemany(sql, rows)
        conn.commit()


def update_run_status(
    db_path: str | Path,
    run_id: str,
    status: str,
    *,
    started_at: str | None = None,
    finished_at: str | None = None,
    error: str | None = None,
) -> None:
    sets = ["status = ?"]
    params: list[Any] = [status]
    if started_at is not None:
        sets.append("started_at = ?")
        params.append(started_at)
    if finished_at is not None:
        sets.append("finished_at = ?")
        params.append(finished_at)
    if error is not None:
        sets.append("error = ?")
        params.append(error)
    params.append(run_id)
    with connect(db_path) as conn:
        conn.execute(f"UPDATE runs SET {', '.join(sets)} WHERE id = ?", params)
        conn.commit()


def get_run(db_path: str | Path, run_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        return None
    return _run_row(row)


def list_runs(db_path: str | Path, limit: int = 50) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_run_row(row) for row in rows]


def _run_row(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    try:
        data["meta"] = json.loads(data.pop("meta_json") or "{}")
    except json.JSONDecodeError:
        data["meta"] = {}
    return data


def list_source_runs(db_path: str | Path, run_id: str) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM source_runs WHERE run_id = ? ORDER BY id ASC", (run_id,)
        ).fetchall()
    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        raw = item.pop("data_json", None)
        try:
            item["data"] = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            item["data"] = None
        output.append(item)
    return output


def insert_entity(
    db_path: str | Path,
    run_id: str,
    kind: str,
    key: str,
    data: dict[str, Any],
    source: str | None = None,
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO entities (run_id, kind, key, data_json, source)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(run_id, kind, key) DO UPDATE SET
                data_json = excluded.data_json,
                source = COALESCE(excluded.source, entities.source)
            """,
            (run_id, kind, key, json.dumps(data, default=str), source),
        )
        conn.commit()


def list_entities(
    db_path: str | Path, run_id: str, kind: str | None = None
) -> list[dict[str, Any]]:
    sql = "SELECT * FROM entities WHERE run_id = ?"
    params: list[Any] = [run_id]
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    sql += " ORDER BY kind ASC, key ASC"
    with connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            item["data"] = json.loads(item.pop("data_json") or "{}")
        except json.JSONDecodeError:
            item["data"] = {}
        output.append(item)
    return output


def insert_observation(
    db_path: str | Path,
    run_id: str,
    *,
    source: str | None,
    category: str,
    severity: str,
    title: str,
    detail: str | None = None,
    data: dict[str, Any] | None = None,
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO observations (run_id, source, category, severity, title, detail, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                source,
                category,
                severity,
                title,
                detail,
                json.dumps(data, default=str) if data is not None else None,
            ),
        )
        conn.commit()


def list_observations(db_path: str | Path, run_id: str) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM observations WHERE run_id = ? ORDER BY id ASC", (run_id,)
        ).fetchall()
    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        raw = item.pop("data_json", None)
        try:
            item["data"] = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            item["data"] = None
        output.append(item)
    return output
