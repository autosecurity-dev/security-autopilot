"""Gitleaks scanner wrapper.

Calls the gitleaks CLI to detect secrets and credentials committed to git history
or present in the working tree.
Requires gitleaks: https://github.com/gitleaks/gitleaks
"""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path


def _finding(leak: dict, project_path: str) -> dict:
    """Normalise a single Gitleaks finding into the unified schema."""
    rule = leak.get("RuleID", "secret-detected")
    file = leak.get("File")
    line = leak.get("StartLine")
    secret_preview = (leak.get("Secret") or "")[:8] + "..." if leak.get("Secret") else "redacted"

    return {
        "id": str(uuid.uuid4()),
        "scanner": "gitleaks",
        "severity": "high",
        "title": f"Secret detected: {rule}",
        "description": (
            f"A potential secret was found matching rule `{rule}`. "
            f"Preview: `{secret_preview}`. Commit: {leak.get('Commit', 'working tree')[:8]}."
        ),
        "file": file,
        "line": line,
        "remediation": (
            "1. Revoke and rotate the exposed credential immediately.\n"
            "2. Remove the secret from git history using `git filter-repo` or BFG.\n"
            "3. Add the file to .gitignore to prevent future commits."
        ),
        "references": [
            "https://github.com/gitleaks/gitleaks",
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
        ],
    }


async def scan(project_path: str) -> list[dict]:
    """Run gitleaks detect against project_path and return normalised findings.

    Silently returns an empty list if gitleaks is not installed.
    """
    findings: list[dict] = []

    proc = await asyncio.create_subprocess_exec(
        "gitleaks", "detect",
        "--source", project_path,
        "--report-format", "json",
        "--report-path", "/dev/stdout",
        "--no-banner",
        "--exit-code", "0",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()

    if proc.returncode not in (0, 1):
        return findings  # not installed or hard error

    try:
        leaks = json.loads(stdout) or []
    except Exception:
        return findings

    for leak in leaks:
        findings.append(_finding(leak, project_path))

    return findings
