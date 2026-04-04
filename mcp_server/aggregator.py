"""Aggregates and caches findings from all scanners in SQLite."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import aiosqlite

DB_PATH = Path.home() / ".security-autopilot" / "findings.db"


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
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.commit()


async def store(findings: list[dict], project_path: str) -> None:
    """Persist a list of findings to the local SQLite cache.

    Args:
        findings: Normalised finding dicts from any scanner.
        project_path: The project root these findings belong to.
    """
    await _ensure_db()
    async with aiosqlite.connect(DB_PATH) as db:
        for f in findings:
            await db.execute(
                """INSERT OR REPLACE INTO findings
                   (id, scanner, severity, title, description, file, line,
                    remediation, references, project_path)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                ),
            )
        await db.commit()


async def get_findings(
    severity: str | None = None,
    project_path: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """Retrieve cached findings from SQLite.

    Args:
        severity: Filter by severity level (critical/high/medium/low/info).
                  If None, returns all severities.
        project_path: Filter to a specific project. If None, returns all.
        limit: Maximum number of findings to return.

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
