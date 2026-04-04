"""Semgrep scanner wrapper.

Runs semgrep with the auto ruleset for SAST (static analysis) findings.
Requires semgrep: https://semgrep.dev/docs/getting-started/
  macOS/Linux: pip install semgrep  (or: brew install semgrep)
"""
from __future__ import annotations

import asyncio
import json
import uuid

SEVERITY_MAP = {
    "ERROR":   "high",
    "WARNING": "medium",
    "INFO":    "info",
}


async def _is_installed() -> bool:
    """Return True if the semgrep binary is available on PATH."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "semgrep", "--version",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()
        return proc.returncode == 0
    except FileNotFoundError:
        return False


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
    if not await _is_installed():
        return [{
            "id": str(uuid.uuid4()),
            "scanner": "semgrep",
            "severity": "info",
            "title": "Semgrep not installed — SAST scan skipped",
            "description": "Install semgrep to enable static analysis security testing.",
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
