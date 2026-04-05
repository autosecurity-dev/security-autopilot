"""Trivy scanner wrapper.

Calls the trivy CLI and normalises its JSON output into the unified finding schema.
Trivy is installed automatically if not present.
"""
from __future__ import annotations

import asyncio
import json
import uuid

from .installer import ensure_installed

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "UNKNOWN":  "info",
}


def _finding(vuln: dict, target: str | None) -> dict:
    """Normalise a single Trivy vulnerability into the unified finding schema."""
    sev_raw = vuln.get("Severity", "UNKNOWN").upper()
    pkg = vuln.get("PkgName", "unknown")
    cve_id = vuln.get("VulnerabilityID", "")
    installed = vuln.get("InstalledVersion", "?")
    fixed = vuln.get("FixedVersion") or "no fix available yet"

    refs = list(vuln.get("References") or [])
    if cve_id and cve_id.startswith("CVE-"):
        refs.insert(0, f"https://nvd.nist.gov/vuln/detail/{cve_id}")

    return {
        "id": str(uuid.uuid4()),
        "scanner": "trivy",
        "severity": SEVERITY_MAP.get(sev_raw, "info"),
        "title": f"{cve_id or 'VULN'} in {pkg}@{installed}",
        "description": (
            vuln.get("Description") or vuln.get("Title") or "No description available."
        ),
        "file": target,
        "line": None,
        "remediation": f"Upgrade `{pkg}` from `{installed}` to `{fixed}`.",
        "references": refs,
    }


async def scan(project_path: str) -> list[dict]:
    """Run trivy fs against project_path and return normalised findings.

    Returns an info finding (not a crash) if trivy is not installed.
    """
    if not await ensure_installed("trivy"):
        return [{
            "id": str(uuid.uuid4()),
            "scanner": "trivy",
            "severity": "info",
            "title": "Trivy could not be installed — CVE scan skipped",
            "description": "Auto-install failed. Please install trivy manually.",
            "file": None,
            "line": None,
            "remediation": "macOS: `brew install trivy`  |  Linux: https://trivy.dev/latest/getting-started/installation/",
            "references": ["https://trivy.dev"],
        }]

    proc = await asyncio.create_subprocess_exec(
        "trivy", "fs", "--format", "json", "--quiet", project_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()

    try:
        data = json.loads(stdout)
    except Exception:
        return []

    findings = []
    for result in data.get("Results", []):
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(_finding(vuln, target))

    return findings
