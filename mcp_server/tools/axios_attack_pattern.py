"""Axios / Sapphire Sleet supply chain attack pattern detector.

Implements all 8 checks from the Microsoft Threat Intelligence report on the
March 31 2026 Sapphire Sleet (North Korean) npm supply chain attack.

Reference: Microsoft Threat Intelligence — Sapphire Sleet axios compromise
Attack window: 2026-03-31 00:21 UTC – 03:15 UTC

Check 1 — known-bad IOC list: handled by KNOWN_BAD in supply_chain.py
Check 2 — C2 network indicator detection in installed files
Check 3 — malicious artifact detection (post-compromise indicators)
Check 4 — auto-update vector detection (^ and ~ pins)
Check 5 — missing lockfile enforcement
Check 6 — transitive dependency exposure
Check 7 — npm cache contamination
Check 8 — CI/CD pipeline exposure window
"""
from __future__ import annotations

import asyncio
import glob
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# C2 indicators from the Microsoft Threat Intelligence report
# These are the exact strings embedded in the malicious payload.
# ---------------------------------------------------------------------------
_C2_INDICATORS = [
    "sfrclak",               # covers sfrclak[.]com and sfrclak.com
    "142.11.206.73",         # C2 IP address
    "hxxp://sfrclak",        # obfuscated C2 URL
    "6202033",               # C2 path used in the attack
    "packages.npm.org/product0",
    "packages.npm.org/product1",
    "packages.npm.org/product2",
]

# Directories inside node_modules that the payload writes to
_PAYLOAD_DIRS = ["plain-crypto-js", "axios"]

# Axios versions whose ^ or ~ pins would auto-resolve to a malicious release
_DANGEROUS_CARET_PINS = {
    "^1.14.0", "~1.14.0",
    "^0.30.0", "~0.30.0",
}

# Compromised axios versions (mirrors KNOWN_BAD for transitive checks)
_COMPROMISED_AXIOS_VERSIONS = {"1.14.1", "0.30.4"}

# Attack window for CI/CD exposure note
_ATTACK_WINDOW = "2026-03-31 00:21 UTC – 03:15 UTC"


# ---------------------------------------------------------------------------
# Finding builder (mirrors supply_chain._finding)
# ---------------------------------------------------------------------------
def _finding(
    severity: str,
    title: str,
    description: str,
    file: str | None,
    remediation: str,
    references: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "scanner": "supply_chain",
        "severity": severity,
        "title": title,
        "description": description,
        "file": file,
        "line": None,
        "remediation": remediation,
        "references": references or ["https://www.microsoft.com/en-us/security/blog/"],
    }


# ---------------------------------------------------------------------------
# Check 2: C2 network indicator detection
# ---------------------------------------------------------------------------
async def _check_c2_indicators(project_path: Path) -> list[dict]:
    """Scan installed package files for embedded C2 indicators."""
    findings: list[dict] = []
    node_modules = project_path / "node_modules"
    if not node_modules.is_dir():
        return findings

    for pkg_dir_name in _PAYLOAD_DIRS:
        pkg_dir = node_modules / pkg_dir_name
        if not pkg_dir.is_dir():
            continue
        # Scan all JS files in the package directory
        for js_file in pkg_dir.rglob("*.js"):
            try:
                content = js_file.read_text(errors="replace")
            except Exception:
                continue
            matched = [ioc for ioc in _C2_INDICATORS if ioc in content]
            if matched:
                findings.append(_finding(
                    severity="critical",
                    title="Active C2 indicator found in installed package",
                    description=(
                        f"The file `{js_file.relative_to(project_path)}` contains "
                        f"known Sapphire Sleet C2 indicators: {matched}. "
                        "This strongly indicates the malicious payload is present on disk."
                    ),
                    file=str(js_file),
                    remediation=(
                        "1. Remove node_modules immediately: `rm -rf node_modules`\n"
                        "2. Run: `npm cache clean --force`\n"
                        "3. Rotate ALL credentials on this machine — assume compromised.\n"
                        "4. Check ~/.security-autopilot/secret-alerts.log for exposed secrets.\n"
                        "5. Treat this machine as compromised and follow your incident response plan."
                    ),
                    references=["https://www.microsoft.com/en-us/security/blog/"],
                ))
                break  # one finding per package dir is enough

    return findings


# ---------------------------------------------------------------------------
# Check 3: Malicious artifact detection (post-compromise indicators)
# ---------------------------------------------------------------------------
async def _check_artifacts() -> list[dict]:
    """Check whether the RAT has already executed and left artifacts on disk."""
    findings: list[dict] = []

    _REMEDIATION = (
        "1. Disconnect from the network immediately.\n"
        "2. Rotate ALL secrets: AWS keys, GitHub tokens, npm tokens, SSH keys, "
        "any credentials that may have been in environment variables or ~/.ssh/.\n"
        "3. Do NOT attempt to clean — rebuild from a known-clean snapshot.\n"
        "4. Review CI/CD pipeline logs for the March 31 2026 00:21–03:15 UTC window.\n"
        "5. Report to your security team immediately."
    )

    artifact_found: str | None = None

    if sys.platform == "darwin":
        # macOS persistence artifact
        if Path("/Library/Caches/com.apple.act.mond").exists():
            artifact_found = "/Library/Caches/com.apple.act.mond"

    elif sys.platform == "win32":
        # Windows artifacts
        wt_exe = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "wt.exe"
        if wt_exe.exists():
            artifact_found = str(wt_exe)
        else:
            temp_dir = Path(os.environ.get("TEMP", "C:/Temp"))
            vbs_files = list(temp_dir.glob("*.vbs")) if temp_dir.is_dir() else []
            if vbs_files:
                artifact_found = str(vbs_files[0])

    elif sys.platform.startswith("linux"):
        # Linux: check for python3 processes spawned from node_modules
        try:
            proc = await asyncio.create_subprocess_exec(
                "ps", "aux",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            ps_output = stdout.decode(errors="replace")
            for line in ps_output.splitlines():
                if "python3" in line and "node_modules" in line:
                    artifact_found = f"suspicious process: {line.strip()[:120]}"
                    break
        except Exception:
            pass

    if artifact_found:
        findings.append(_finding(
            severity="critical",
            title="Machine may be compromised — Sapphire Sleet RAT artifact detected",
            description=(
                f"A file or process associated with the North Korean Sapphire Sleet RAT "
                f"deployed via the axios supply chain attack was found on this machine: "
                f"`{artifact_found}`."
            ),
            file=artifact_found if not artifact_found.startswith("suspicious") else None,
            remediation=_REMEDIATION,
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 4: Auto-update vector detection
# ---------------------------------------------------------------------------
def _check_autoupdate_vector(pkg_json_path: Path) -> list[dict]:
    """Flag axios pins that would auto-resolve to a malicious version."""
    findings: list[dict] = []
    try:
        data = json.loads(pkg_json_path.read_text())
    except Exception:
        return findings

    all_deps = {
        **data.get("dependencies", {}),
        **data.get("devDependencies", {}),
    }

    axios_spec = all_deps.get("axios", "")
    if not axios_spec:
        return findings

    spec_lower = axios_spec.strip().lower()
    is_dangerous = (
        axios_spec in _DANGEROUS_CARET_PINS
        or spec_lower in ("latest", "*")
    )

    if is_dangerous:
        findings.append(_finding(
            severity="high",
            title="axios version pin allows silent upgrade to malicious version",
            description=(
                f"The axios dependency is pinned as `{axios_spec}`, which would "
                "automatically resolve to axios@1.14.1 or axios@0.30.4 — the versions "
                "used in the March 31 2026 Sapphire Sleet supply chain attack."
            ),
            file=str(pkg_json_path),
            remediation=(
                "Change to an exact pin: `\"axios\": \"1.14.0\"`\n"
                "Run: `npm install --save-exact axios@1.14.0`\n"
                "Commit package-lock.json to version control.\n"
                "Use `npm ci` instead of `npm install` in all CI/CD pipelines."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 5: Missing lockfile enforcement
# ---------------------------------------------------------------------------
def _check_missing_lockfile(project_path: Path) -> list[dict]:
    """Flag projects that have package.json but no lockfile."""
    pkg_json = project_path / "package.json"
    pkg_lock = project_path / "package-lock.json"
    yarn_lock = project_path / "yarn.lock"

    if pkg_json.exists() and not pkg_lock.exists() and not yarn_lock.exists():
        return [_finding(
            severity="high",
            title="No lockfile — supply chain attacks like axios bypass npm audit",
            description=(
                "This project has package.json but no package-lock.json or yarn.lock. "
                "Without a lockfile, `npm install` resolves versions at runtime and can "
                "silently pull in a newly-published malicious version (as happened with "
                "axios@1.14.1 on March 31 2026)."
            ),
            file=str(pkg_json),
            remediation=(
                "Run `npm install` to generate package-lock.json, then commit it.\n"
                "Use `npm ci` in CI/CD pipelines — it enforces the lockfile exactly."
            ),
        )]
    return []


# ---------------------------------------------------------------------------
# Check 6: Transitive dependency exposure
# ---------------------------------------------------------------------------
def _check_transitive_deps(pkg_lock_path: Path) -> list[dict]:
    """Find packages that pulled in a compromised axios version as a transitive dep."""
    findings: list[dict] = []
    try:
        data = json.loads(pkg_lock_path.read_text())
    except Exception:
        return findings

    packages = data.get("packages", {}) or {}

    # Find which top-level packages depend on the compromised axios
    for pkg_path, pkg_data in packages.items():
        if not pkg_path.startswith("node_modules/"):
            continue
        # Skip axios itself — already caught by KNOWN_BAD
        pkg_name = pkg_path.removeprefix("node_modules/")
        if pkg_name == "axios":
            continue

        nested_deps = {
            **pkg_data.get("dependencies", {}),
            **pkg_data.get("peerDependencies", {}),
        }
        axios_dep = nested_deps.get("axios", "")
        if not axios_dep:
            continue

        resolved = axios_dep.lstrip("^~=>< ")
        if resolved in _COMPROMISED_AXIOS_VERSIONS:
            findings.append(_finding(
                severity="critical",
                title=f"Transitive dependency resolved to compromised axios version",
                description=(
                    f"`{pkg_name}` depends on `axios@{resolved}`, which is a compromised "
                    "version used in the March 31 2026 Sapphire Sleet supply chain attack. "
                    "You did not install axios directly — a package you depend on pulled "
                    "in the compromised version. This is how the attack reached most victims; "
                    "`npm audit` would not have caught this."
                ),
                file=str(pkg_lock_path),
                remediation=(
                    f"Add an overrides section to package.json:\n"
                    '  {"overrides": {"axios": "1.14.0"}}\n'
                    "Then run: `npm install && npm cache clean --force`"
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Check 7: npm cache contamination
# ---------------------------------------------------------------------------
async def _check_npm_cache() -> list[dict]:
    """Check npm cache for compromised axios versions."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "npm", "cache", "verify",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode(errors="replace")
    except (FileNotFoundError, asyncio.TimeoutError, Exception):
        return []  # npm not installed or timed out — skip silently

    contaminated = []
    for bad_ver in _COMPROMISED_AXIOS_VERSIONS:
        if f"axios@{bad_ver}" in output or f"axios/{bad_ver}" in output:
            contaminated.append(bad_ver)

    if contaminated:
        return [_finding(
            severity="high",
            title="Compromised axios version found in npm cache",
            description=(
                f"The npm cache contains axios@{', '.join(contaminated)}, "
                "which is a compromised version from the Sapphire Sleet attack. "
                "The malicious payload included a persistence hook that re-fetches "
                "itself from cache. Cleaning the cache removes this vector."
            ),
            file=None,
            remediation="Run: `npm cache clean --force`",
        )]

    return []


# ---------------------------------------------------------------------------
# Check 8: CI/CD pipeline exposure window
# ---------------------------------------------------------------------------
def _check_cicd_pipelines(project_path: Path) -> list[dict]:
    """Scan CI/CD config files for npm install usage during the attack window."""
    findings: list[dict] = []

    patterns = [
        str(project_path / ".github" / "workflows" / "*.yml"),
        str(project_path / ".github" / "workflows" / "*.yaml"),
        str(project_path / ".gitlab-ci.yml"),
        str(project_path / ".circleci" / "config.yml"),
    ]

    ci_files = []
    for pattern in patterns:
        ci_files.extend(glob.glob(pattern))

    for ci_file in ci_files:
        try:
            content = Path(ci_file).read_text()
        except Exception:
            continue

        lines = content.splitlines()
        uses_npm_install = any(
            "npm install" in line and "npm ci" not in line
            for line in lines
        )
        missing_node_pin = "node-version" not in content

        if uses_npm_install or missing_node_pin:
            issues = []
            if uses_npm_install:
                issues.append("`npm install` (not `npm ci`) — does not enforce lockfile")
            if missing_node_pin:
                issues.append("no pinned Node.js version")

            findings.append(_finding(
                severity="info",
                title="CI pipeline may have pulled compromised axios during attack window",
                description=(
                    f"`{Path(ci_file).name}` uses {' and '.join(issues)}. "
                    f"If this CI ran between {_ATTACK_WINDOW}, it may have "
                    "installed axios@1.14.1. Check your CI logs for that exact window."
                ),
                file=ci_file,
                remediation=(
                    f"1. Check CI logs for runs between {_ATTACK_WINDOW}.\n"
                    "2. Replace `npm install` with `npm ci` in all pipeline steps.\n"
                    "3. Pin Node.js version explicitly (e.g. `node-version: '20.x'`)."
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
async def run_axios_checks(project_path: str) -> list[dict]:
    """Run all Sapphire Sleet / axios attack pattern checks.

    These checks are based on the Microsoft Threat Intelligence report on the
    March 31 2026 axios supply chain compromise. Some checks are machine-level
    (artifact detection, cache contamination) and run even when no package.json
    is present.

    Args:
        project_path: Absolute path to the project root.

    Returns:
        List of finding dicts conforming to schemas/finding.json.
        Never raises — all errors are caught and silently dropped.
    """
    root = Path(project_path)
    findings: list[dict] = []

    try:
        # Check 2: C2 indicators in installed files
        findings.extend(await _check_c2_indicators(root))

        # Check 3: Post-compromise artifacts on disk
        findings.extend(await _check_artifacts())

        pkg_json = root / "package.json"
        pkg_lock = root / "package-lock.json"

        if pkg_json.exists():
            # Check 4: Auto-update vector
            findings.extend(_check_autoupdate_vector(pkg_json))

        # Check 5: Missing lockfile
        findings.extend(_check_missing_lockfile(root))

        if pkg_lock.exists():
            # Check 6: Transitive dependency exposure
            findings.extend(_check_transitive_deps(pkg_lock))

        # Check 7: npm cache contamination (machine-level)
        findings.extend(await _check_npm_cache())

        # Check 8: CI/CD pipeline exposure window
        findings.extend(_check_cicd_pipelines(root))

    except Exception:
        pass  # never block a scan

    return findings
