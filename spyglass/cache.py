from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from .db import connect, init_db


def make_key(*parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return f"v1:{digest}"


class Cache:
    """Small SQLite-backed TTL cache. Values must be JSON serializable."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        init_db(self.db_path)

    def get(self, key: str) -> Any | None:
        now = time.time()
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
            ).fetchone()
            if row is None:
                return None
            if row["expires_at"] <= now:
                conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                conn.commit()
                return None
        try:
            return json.loads(row["value"])
        except (TypeError, json.JSONDecodeError):
            return None

    def set(self, key: str, value: Any, ttl: int) -> None:
        if ttl <= 0:
            return
        now = time.time()
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        with connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO cache (key, value, expires_at, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    expires_at = excluded.expires_at,
                    created_at = excluded.created_at
                """,
                (key, payload, now + ttl, now),
            )
            conn.commit()

    def delete(self, key: str) -> None:
        with connect(self.db_path) as conn:
            conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            conn.commit()

    def purge_expired(self) -> int:
        with connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM cache WHERE expires_at <= ?", (time.time(),))
            conn.commit()
            return cursor.rowcount

    def clear(self) -> None:
        with connect(self.db_path) as conn:
            conn.execute("DELETE FROM cache")
            conn.commit()


def cache_stats(db_path: str | Path) -> dict[str, int]:
    try:
        with connect(db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS entries, "
                "SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END) AS live "
                "FROM cache",
                (time.time(),),
            ).fetchone()
        return {"entries": row["entries"], "live": row["live"] or 0}
    except sqlite3.Error:
        return {"entries": 0, "live": 0}
