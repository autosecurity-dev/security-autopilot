"""Gitleaks scanner wrapper.

Detects secrets and credentials in the working tree (no git history required).
Gitleaks is installed automatically if not present.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
import uuid
from pathlib import Path

from .installer import ensure_installed


def _finding(leak: dict) -> dict:
    """Normalise a single Gitleaks result into the unified finding schema."""
    rule = leak.get("RuleID", "secret-detected")
    file = leak.get("File", "unknown")
    line = leak.get("StartLine")
    secret_raw = leak.get("Secret") or ""
    preview = (secret_raw[:8] + "...") if len(secret_raw) > 8 else "redacted"

    return {
        "id": str(uuid.uuid4()),
        "scanner": "gitleaks",
        "severity": "high",
        "title": f"Exposed {rule} secret in {file}",
        "description": (
            f"A `{rule}` credential was found in `{file}` "
            f"(line {line}). Preview: `{preview}`. "
            f"Commit: {(leak.get('Commit') or 'working tree')[:8]}."
        ),
        "file": file,
        "line": line,
        "remediation": (
            f"1. Rotate this credential immediately — assume it is compromised.\n"
            f"2. Add `{file}` to .gitignore to prevent future commits.\n"
            f"3. If committed to git history, purge with `git filter-repo --path {file} --invert-paths`."
        ),
        "references": [
            "https://github.com/gitleaks/gitleaks",
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
        ],
    }


async def scan(project_path: str) -> list[dict]:
    """Run gitleaks detect on project_path (no-git mode) and return normalised findings.

    Writes the report to a temp file to avoid stdout/stderr interleaving issues.
    Returns an info finding (not a crash) if gitleaks is not installed.
    """
    if not await ensure_installed("gitleaks"):
        return [{
            "id": str(uuid.uuid4()),
            "scanner": "gitleaks",
            "severity": "info",
            "title": "Gitleaks could not be installed — secret scan skipped",
            "description": "Auto-install failed. Please install gitleaks manually.",
            "file": None,
            "line": None,
            "remediation": "macOS: `brew install gitleaks`  |  https://github.com/gitleaks/gitleaks#installing",
            "references": ["https://github.com/gitleaks/gitleaks"],
        }]

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    # Exclude build artifacts and dependency folders — scanning these
    # produces overwhelming false positives (compiled JS, cache files, etc.)
    ignore_paths = [
        ".next", "dist", "build", "out", ".nuxt", ".output",
        "node_modules", ".git", "__pycache__", ".venv", "venv",
        ".tox", "coverage", ".nyc_output", "*.min.js",
    ]
    ignore_args: list[str] = []
    for p in ignore_paths:
        ignore_args += ["--ignore-path", p]

    proc = await asyncio.create_subprocess_exec(
        "gitleaks", "detect",
        "--source", project_path,
        "--report-format", "json",
        "--report-path", report_path,
        "--no-git",
        "--no-banner",
        "--exit-code", "0",
        *ignore_args,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.communicate()

    try:
        report_file = Path(report_path)
        if not report_file.exists() or report_file.stat().st_size == 0:
            return []
        leaks = json.loads(report_file.read_text()) or []
    except Exception:
        return []
    finally:
        Path(report_path).unlink(missing_ok=True)

    return [_finding(leak) for leak in leaks]
