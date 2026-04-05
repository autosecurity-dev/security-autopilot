"""SQLite cache for dynamically fetched threat data.

Stores threats pulled from OSV, npm advisories, etc. in the same
findings.db database — new table, no interference with existing findings.
TTL: 24 hours. Falls back gracefully if DB is unavailable.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

import aiosqlite

log = logging.getLogger(__name__)

DB_PATH = Path.home() / ".security-autopilot" / "findings.db"
_TTL_HOURS = 24


async def _ensure_table() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS threat_cache (
                name       TEXT NOT NULL,
                version    TEXT NOT NULL,
                reason     TEXT NOT NULL,
                source     TEXT NOT NULL,
                fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (name, version, source)
            )
        """)
        await db.commit()


async def load_cached_threats() -> list[dict]:
    """Return all cached threats fetched within the last 24 hours."""
    try:
        await _ensure_table()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=_TTL_HOURS)).isoformat()
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT name, version, reason, source FROM threat_cache WHERE fetched_at > ?",
                (cutoff,),
            ) as cursor:
                rows = await cursor.fetchall()
        return [{"name": r["name"], "version": r["version"], "reason": r["reason"]} for r in rows]
    except Exception as exc:
        log.debug("Could not load cached threats: %s", exc)
        return []


async def save_threats(threats: list[dict]) -> None:
    """Persist fetched threats to the cache, replacing stale entries."""
    if not threats:
        return
    try:
        await _ensure_table()
        now = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(DB_PATH) as db:
            await db.executemany(
                """INSERT OR REPLACE INTO threat_cache (name, version, reason, source, fetched_at)
                   VALUES (?, ?, ?, ?, ?)""",
                [
                    (t["name"], t["version"], t["reason"], t.get("source", "unknown"), now)
                    for t in threats
                ],
            )
            await db.commit()
        log.info("Threat cache updated — %d entries saved", len(threats))
    except Exception as exc:
        log.warning("Could not save threat cache: %s", exc)


async def get_last_fetch_time() -> datetime | None:
    """Return the most recent fetched_at timestamp across all cached threats."""
    try:
        await _ensure_table()
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                "SELECT MAX(fetched_at) FROM threat_cache"
            ) as cursor:
                row = await cursor.fetchone()
        if row and row[0]:
            return datetime.fromisoformat(row[0])
    except Exception:
        pass
    return None
