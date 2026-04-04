"""Trivy scanner wrapper.

Calls the trivy CLI and normalises its JSON output into the unified finding schema.
Requires trivy to be installed: https://trivy.dev/latest/getting-started/installation/
"""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path


SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


def _finding(vuln: dict, file: str | None) -> dict:
    """Normalise a single Trivy vulnerability into the unified schema."""
    sev_raw = vuln.get("Severity", "UNKNOWN").upper()
    return {
        "id": str(uuid.uuid4()),
        "scanner": "trivy",
        "severity": SEVERITY_MAP.get(sev_raw, "info"),
        "title": f"{vuln.get('VulnerabilityID', 'Unknown')} in {vuln.get('PkgName', '?')}",
        "description": vuln.get("Description") or vuln.get("Title") or "No description available.",
        "file": file,
        "line": None,
        "remediation": (
            f"Upgrade `{vuln.get('PkgName')}` from "
            f"`{vuln.get('InstalledVersion', '?')}` to "
            f"`{vuln.get('FixedVersion', 'latest')}`."
        ),
        "references": vuln.get("References") or [],
    }


async def scan(project_path: str) -> list[dict]:
    """Run trivy fs against project_path and return normalised findings.

    Silently returns an empty list if trivy is not installed.
    """
    findings: list[dict] = []

    proc = await asyncio.create_subprocess_exec(
        "trivy", "fs", "--format", "json", "--quiet", project_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode not in (0, 1):
        # trivy not installed or hard error — skip silently
        return findings

    try:
        data = json.loads(stdout)
    except Exception:
        return findings

    for result in data.get("Results", []):
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(_finding(vuln, target))

    return findings
