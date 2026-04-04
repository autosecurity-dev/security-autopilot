"""Semgrep scanner wrapper.

Runs semgrep with the auto ruleset for SAST (static analysis) findings.
Semgrep is installed automatically if not present.
"""
from __future__ import annotations

import asyncio
import json
import uuid

from .installer import ensure_installed

SEVERITY_MAP = {
    "ERROR":   "high",
    "WARNING": "medium",
    "INFO":    "info",
}


def _finding(result: dict) -> dict:
    """Normalise a single Semgrep result into the unified finding schema."""
    extra = result.get("extra", {})
    sev_raw = extra.get("severity", "INFO").upper()
    meta = extra.get("metadata", {})
    rule_id = result.get("check_id", "semgrep-finding")
    message = extra.get("message", "No description.")

    # Semgrep sometimes provides an autofix
    fix = extra.get("fix") or meta.get("fix") or ""
    remediation = (
        f"Apply fix: `{fix}`" if fix
        else f"Review rule `{rule_id}` and remediate the flagged code pattern."
    )

    refs = list(meta.get("references") or [])
    if meta.get("cwe"):
        cwes = meta["cwe"] if isinstance(meta["cwe"], list) else [meta["cwe"]]
        for cwe in cwes:
            refs.append(f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html")

    return {
        "id": str(uuid.uuid4()),
        "scanner": "semgrep",
        "severity": SEVERITY_MAP.get(sev_raw, "info"),
        "title": rule_id,
        "description": f"[{rule_id}] {message}",
        "file": result.get("path"),
        "line": result.get("start", {}).get("line"),
        "remediation": remediation,
        "references": refs,
    }


async def scan(project_path: str) -> list[dict]:
    """Run semgrep --config=auto against project_path and return normalised findings.

    Returns an info finding (not a crash) if semgrep is not installed.
    """
    if not await ensure_installed("semgrep"):
        return [{
            "id": str(uuid.uuid4()),
            "scanner": "semgrep",
            "severity": "info",
            "title": "Semgrep could not be installed — SAST scan skipped",
            "description": "Auto-install failed. Please install semgrep manually.",
            "file": None,
            "line": None,
            "remediation": "`pip install semgrep`  or  `brew install semgrep`",
            "references": ["https://semgrep.dev"],
        }]

    proc = await asyncio.create_subprocess_exec(
        "semgrep", "--config=auto", "--json", "--quiet", project_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()

    try:
        data = json.loads(stdout)
    except Exception:
        return []

    return [_finding(r) for r in data.get("results", [])]
