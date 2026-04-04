"""Orchestrates all scanners for a full repo or single file scan."""
from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path

from . import supply_chain, trivy, gitleaks, semgrep

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_SCANNER_MAP = {
    "supply_chain": supply_chain,
    "trivy":        trivy,
    "gitleaks":     gitleaks,
    "semgrep":      semgrep,
}


def _deduplicate(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings by (scanner, title, file) key."""
    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (f.get("scanner"), f.get("title"), f.get("file"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _sort_by_severity(findings: list[dict]) -> list[dict]:
    """Sort findings critical → high → medium → low → info."""
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4))


async def scan_repo(path: str, checks: list[str] | None = None) -> dict:
    """Run all requested scanners in parallel against a project directory.

    Args:
        path: Absolute path to the project root.
        checks: Scanner names to run. Defaults to ["all"].

    Returns:
        Dict with keys: summary, findings, top_priority.
    """
    if not checks:
        checks = ["all"]

    run_all = "all" in checks
    scanners_to_run = {
        name: mod
        for name, mod in _SCANNER_MAP.items()
        if run_all or name in checks
    }

    start = time.monotonic()
    results = await asyncio.gather(
        *[mod.scan(path) for mod in scanners_to_run.values()],
        return_exceptions=True,
    )
    duration = round(time.monotonic() - start, 2)

    all_findings: list[dict] = []
    for result in results:
        if isinstance(result, list):
            all_findings.extend(result)

    all_findings = _sort_by_severity(_deduplicate(all_findings))

    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

    top_priority = next(
        (f for f in all_findings if f.get("severity") in ("critical", "high")),
        None,
    )

    return {
        "summary": {
            **counts,
            "scanners_run": list(scanners_to_run.keys()),
            "scan_duration_seconds": duration,
            "scanned_path": path,
        },
        "findings": all_findings,
        "top_priority": top_priority,
    }


async def scan_file(filepath: str) -> dict:
    """Run supply chain and semgrep checks on a single file.

    Args:
        filepath: Absolute path to the file.

    Returns:
        Dict with keys: summary, findings, top_priority.
    """
    path = Path(filepath)
    findings: list[dict] = []

    tasks = []
    if path.name in ("package.json", "package-lock.json", "requirements.txt"):
        tasks.append(supply_chain.scan(str(path.parent)))
    tasks.append(semgrep.scan(filepath))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    findings = _sort_by_severity(_deduplicate(findings))

    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

    top_priority = next(
        (f for f in findings if f.get("severity") in ("critical", "high")),
        None,
    )

    return {
        "summary": {
            **counts,
            "scanners_run": ["supply_chain", "semgrep"],
            "scan_duration_seconds": 0,
            "scanned_path": filepath,
        },
        "findings": findings,
        "top_priority": top_priority,
    }
