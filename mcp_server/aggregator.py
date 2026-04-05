"""Aggregates and caches findings from all scanners in SQLite."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

import aiosqlite

DB_PATH = Path.home() / ".security-autopilot" / "findings.db"

_DEFAULT_MAX_AGE_DAYS = 7


async def _ensure_db() -> None:
    """Create the findings database and table if they don't exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scanner TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                file TEXT,
                line INTEGER,
                remediation TEXT,
                references TEXT,
                project_path TEXT,
                scanned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            )
        """)
        # Add scanned_at column to existing DBs that pre-date this migration
        try:
            await db.execute("ALTER TABLE findings ADD COLUMN scanned_at TEXT")
        except Exception:
            pass  # column already exists
        await db.commit()


async def store(findings: list[dict], project_path: str) -> None:
    """Persist a list of findings to the local SQLite cache.

    Deletes all previous findings for this project before inserting new ones
    so the cache always reflects the latest scan and never accumulates stale rows.

    Args:
        findings: Normalised finding dicts from any scanner.
        project_path: The project root these findings belong to.
    """
    await _ensure_db()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with aiosqlite.connect(DB_PATH) as db:
        # Clear stale findings for this project before writing fresh ones
        await db.execute(
            "DELETE FROM findings WHERE project_path = ?",
            (project_path,),
        )
        for f in findings:
            await db.execute(
                """INSERT OR REPLACE INTO findings
                   (id, scanner, severity, title, description, file, line,
                    remediation, references, project_path, scanned_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f.get("id", str(uuid.uuid4())),
                    f.get("scanner", "unknown"),
                    f.get("severity", "info"),
                    f.get("title", ""),
                    f.get("description", ""),
                    f.get("file"),
                    f.get("line"),
                    f.get("remediation", ""),
                    json.dumps(f.get("references", [])),
                    project_path,
                    now,
                ),
            )
        await db.commit()


async def get_findings(
    severity: str | None = None,
    project_path: str | None = None,
    limit: int = 200,
    max_age_days: int = _DEFAULT_MAX_AGE_DAYS,
) -> list[dict]:
    """Retrieve cached findings from SQLite.

    Args:
        severity: Filter by severity level (critical/high/medium/low/info).
                  If None, returns all severities.
        project_path: Filter to a specific project. If None, returns all.
        limit: Maximum number of findings to return.
        max_age_days: Only return findings scanned within this many days.
                      Defaults to 7. Pass 0 to disable the age filter.

    Returns:
        List of finding dicts ordered by severity (critical first).
    """
    await _ensure_db()

    severity_order = "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"

    conditions = []
    params: list = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if project_path:
        conditions.append("project_path = ?")
        params.append(project_path)
    if max_age_days > 0:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        conditions.append("(scanned_at IS NULL OR scanned_at >= ?)")
        params.append(cutoff)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.append(limit)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            f"SELECT * FROM findings {where} ORDER BY {severity_order}, scanned_at DESC LIMIT ?",
            params,
        )
        rows = await cursor.fetchall()

    return [
        {
            "id": row["id"],
            "scanner": row["scanner"],
            "severity": row["severity"],
            "title": row["title"],
            "description": row["description"],
            "file": row["file"],
            "line": row["line"],
            "remediation": row["remediation"],
            "references": json.loads(row["references"] or "[]"),
            "project_path": row["project_path"],
            "scanned_at": row["scanned_at"],
        }
        for row in rows
    ]
