"""Small SQLite-backed JSON TTL cache."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from depguard.config import get_settings


class SQLiteCache:
    """Store JSON responses with expiry and optional stale fallback."""

    def __init__(self, path: Path | None = None, ttl_seconds: int | None = None) -> None:
        settings = get_settings()
        self.path = path or settings.cache_path
        self.ttl_seconds = ttl_seconds or settings.cache_ttl_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS cache_entries "
                "(cache_key TEXT PRIMARY KEY, payload TEXT NOT NULL, expires_at REAL NOT NULL)"
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get(self, key: str, *, allow_stale: bool = False) -> tuple[Any, bool] | None:
        """Return cached payload and a stale flag when present."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, expires_at FROM cache_entries WHERE cache_key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        stale = float(row[1]) < time.time()
        if stale and not allow_stale:
            return None
        return json.loads(row[0]), stale

    def set(self, key: str, payload: Any) -> None:
        """Insert or refresh one cache record."""
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO cache_entries(cache_key, payload, expires_at) VALUES (?, ?, ?) "
                "ON CONFLICT(cache_key) DO UPDATE SET payload=excluded.payload, "
                "expires_at=excluded.expires_at",
                (key, json.dumps(payload), time.time() + self.ttl_seconds),
            )

    def clear(self) -> int:
        """Remove all cached responses and return the number removed."""
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM cache_entries")
            return cursor.rowcount

    def stats(self) -> dict[str, int]:
        """Return cache record and expired-record counts."""
        with self._connect() as connection:
            total, expired = connection.execute(
                "SELECT COUNT(*), SUM(expires_at < ?) FROM cache_entries", (time.time(),)
            ).fetchone()
        return {"entries": int(total or 0), "expired": int(expired or 0)}
