"""Auto-patch for known-malicious packages.

When the daemon detects a CRITICAL supply_chain finding, this module:
1. Parses the bad package name and version from the finding title
2. Finds the latest safe version within the same major (semver-compatible)
3. Applies the patch via npm or pip
4. Returns a result dict describing what was changed

Never patches across major versions — compatibility is guaranteed by semver contract.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any


# Pattern: "Known-malicious package: axios@1.14.1"
_TITLE_RE = re.compile(r"Known-malicious package:\s*([^@]+)@(.+)")


async def auto_patch(project_path: str, finding: dict[str, Any]) -> dict | None:
    """Attempt to auto-patch a known-malicious package finding.

    Args:
        project_path: Absolute path to the project root.
        finding: A supply_chain CRITICAL finding dict.

    Returns:
        Dict with patch details if successful, None if patch not possible.
    """
    match = _TITLE_RE.search(finding.get("title", ""))
    if not match:
        return None

    package, bad_version = match.group(1).strip(), match.group(2).strip()
    project = Path(project_path)

    if (project / "package.json").exists():
        return await _patch_npm(project, package, bad_version)
    if (project / "requirements.txt").exists():
        return await _patch_pip(project, package, bad_version)

    return None


# ── npm ───────────────────────────────────────────────────────────────────────

async def _patch_npm(project: Path, package: str, bad_version: str) -> dict | None:
    safe = await _safe_version_npm(package, bad_version)
    if not safe:
        return None

    ok = await _run(["npm", "install", f"{package}@{safe}"], cwd=str(project))
    return {"package": package, "from": bad_version, "to": safe, "success": ok, "manager": "npm"}


async def _safe_version_npm(package: str, bad_version: str) -> str | None:
    """Return highest safe npm version with same major as bad_version."""
    proc = await asyncio.create_subprocess_exec(
        "npm", "view", package, "versions", "--json",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    if proc.returncode != 0:
        return None

    try:
        versions: list[str] = json.loads(stdout)
    except json.JSONDecodeError:
        return None

    bad_major = _major(bad_version)
    candidates = [
        v for v in versions
        if _major(v) == bad_major and v != bad_version and not _is_prerelease(v)
    ]
    return candidates[-1] if candidates else None


# ── pip ───────────────────────────────────────────────────────────────────────

async def _patch_pip(project: Path, package: str, bad_version: str) -> dict | None:
    safe = await _safe_version_pip(package, bad_version)
    if not safe:
        return None

    ok = await _run(["pip", "install", f"{package}=={safe}", "-q"], cwd=str(project))
    if ok:
        # Update requirements.txt pin
        _update_requirements(project / "requirements.txt", package, bad_version, safe)
    return {"package": package, "from": bad_version, "to": safe, "success": ok, "manager": "pip"}


async def _safe_version_pip(package: str, bad_version: str) -> str | None:
    """Return highest safe pip version with same major as bad_version."""
    proc = await asyncio.create_subprocess_exec(
        "pip", "index", "versions", package,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    if proc.returncode != 0:
        return None

    # Output: "package (x.y.z) Available versions: a, b, c, ..."
    text = stdout.decode()
    m = re.search(r"Available versions:\s*(.+)", text)
    if not m:
        return None

    versions = [v.strip() for v in m.group(1).split(",")]
    bad_major = _major(bad_version)
    candidates = [
        v for v in versions
        if _major(v) == bad_major and v != bad_version and not _is_prerelease(v)
    ]
    return candidates[0] if candidates else None  # pip returns newest first


def _update_requirements(req_file: Path, package: str, old_ver: str, new_ver: str) -> None:
    if not req_file.exists():
        return
    text = req_file.read_text()
    text = re.sub(
        rf"(?i){re.escape(package)}=={re.escape(old_ver)}",
        f"{package}=={new_ver}",
        text,
    )
    req_file.write_text(text)


# ── helpers ───────────────────────────────────────────────────────────────────

def _major(version: str) -> str:
    return version.split(".")[0]


def _is_prerelease(version: str) -> bool:
    return any(tag in version.lower() for tag in ("alpha", "beta", "rc", "dev", "pre"))


async def _run(cmd: list[str], cwd: str) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return proc.returncode == 0
    except Exception:
        return False
