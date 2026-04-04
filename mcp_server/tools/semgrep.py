"""Semgrep scanner wrapper.

Runs semgrep with the auto ruleset and normalises output into the unified schema.
Requires semgrep: https://semgrep.dev/docs/getting-started/
"""
from __future__ import annotations

import asyncio
import json
import uuid


SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "info",
}


def _finding(result: dict) -> dict:
    """Normalise a single Semgrep result into the unified schema."""
    extra = result.get("extra", {})
    sev_raw = extra.get("severity", "INFO").upper()
    meta = extra.get("metadata", {})

    return {
        "id": str(uuid.uuid4()),
        "scanner": "semgrep",
        "severity": SEVERITY_MAP.get(sev_raw, "info"),
        "title": result.get("check_id", "semgrep-finding"),
        "description": extra.get("message", "No description."),
        "file": result.get("path"),
        "line": result.get("start", {}).get("line"),
        "remediation": meta.get("fix") or "Review the flagged code and apply the suggested fix from the Semgrep rule.",
        "references": meta.get("references") or [],
    }


async def scan(project_path: str) -> list[dict]:
    """Run semgrep --config auto against project_path and return normalised findings.

    Silently returns an empty list if semgrep is not installed.
    """
    findings: list[dict] = []

    proc = await asyncio.create_subprocess_exec(
        "semgrep", "--config", "auto",
        "--json", "--quiet",
        project_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()

    if proc.returncode not in (0, 1):
        return findings

    try:
        data = json.loads(stdout)
    except Exception:
        return findings

    for result in data.get("results", []):
        findings.append(_finding(result))

    return findings
