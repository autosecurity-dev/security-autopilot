"""Orchestrates all scanners for a full repo or single file scan."""
from __future__ import annotations

import asyncio
from pathlib import Path

from . import supply_chain, trivy, gitleaks, semgrep


VALID_CHECKS = {"all", "supply_chain", "trivy", "gitleaks", "semgrep"}


async def scan_repo(path: str, checks: list[str] | None = None) -> dict:
    """Run all requested scanners against a project directory.

    Args:
        path: Absolute path to the project root.
        checks: List of scanner names to run. Defaults to ["all"].

    Returns:
        Dict with keys: path, findings (list), summary (counts by severity).
    """
    if not checks:
        checks = ["all"]

    run_all = "all" in checks
    tasks = []

    if run_all or "supply_chain" in checks:
        tasks.append(supply_chain.scan(path))
    if run_all or "trivy" in checks:
        tasks.append(trivy.scan(path))
    if run_all or "gitleaks" in checks:
        tasks.append(gitleaks.scan(path))
    if run_all or "semgrep" in checks:
        tasks.append(semgrep.scan(path))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings = []
    for result in results:
        if isinstance(result, list):
            all_findings.extend(result)

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        summary[sev] = summary.get(sev, 0) + 1

    return {"path": path, "findings": all_findings, "summary": summary}


async def scan_file(filepath: str) -> dict:
    """Run supply chain and semgrep checks on a single file.

    Args:
        filepath: Absolute path to the file.

    Returns:
        Dict with keys: file, findings (list), summary (counts by severity).
    """
    path = Path(filepath)
    findings = []

    # Supply chain covers package.json / package-lock.json / requirements.txt
    if path.name in ("package.json", "package-lock.json", "requirements.txt"):
        findings.extend(await supply_chain.scan(str(path.parent)))

    # Semgrep can scan any source file
    findings.extend(await semgrep.scan(filepath))

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        summary[sev] = summary.get(sev, 0) + 1

    return {"file": filepath, "findings": findings, "summary": summary}
