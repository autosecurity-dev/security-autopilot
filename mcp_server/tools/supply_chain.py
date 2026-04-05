"""Supply chain security scanner.

Checks package manifests for known-bad versions, maintainer hijack signals,
floating pins, lifecycle script injection, and SLSA provenance gaps.
Specifically built to catch attacks like the March 2026 axios npm compromise.
"""
from __future__ import annotations

import json
import uuid
import asyncio
import tempfile
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Known-bad version blocklist
# ---------------------------------------------------------------------------
KNOWN_BAD: list[dict[str, str]] = [
    {"name": "axios",          "version": "1.14.1",  "reason": "supply chain RAT March 2026 — postinstall dropper"},
    {"name": "axios",          "version": "0.30.4",  "reason": "supply chain RAT March 2026 — postinstall dropper"},
    {"name": "plain-crypto-js","version": "4.2.1",   "reason": "axios attack dropper — remote access trojan"},
]


async def _get_known_bad() -> list[dict]:
    """Return merged blocklist: hardcoded KNOWN_BAD + live-cached threats (24h TTL)."""
    try:
        from .threat_cache import load_cached_threats
        cached = await load_cached_threats()
    except Exception:
        cached = []
    seen: set[tuple[str, str]] = {(e["name"], e["version"]) for e in KNOWN_BAD}
    merged = list(KNOWN_BAD)
    for entry in cached:
        key = (entry["name"], entry["version"])
        if key not in seen:
            seen.add(key)
            merged.append(entry)
    return merged

LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}

COOLDOWN_HOURS = 72  # flag versions published within this window


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------
def _finding(
    severity: str,
    title: str,
    description: str,
    file: str | None,
    remediation: str,
    references: list[str] | None = None,
) -> dict[str, Any]:
    """Build a normalized finding dict matching schemas/finding.json."""
    return {
        "id": str(uuid.uuid4()),
        "scanner": "supply_chain",
        "severity": severity,
        "title": title,
        "description": description,
        "file": file,
        "line": None,
        "remediation": remediation,
        "references": references or [],
    }


# ---------------------------------------------------------------------------
# npm registry helpers
# ---------------------------------------------------------------------------
async def _fetch_npm_metadata(client: httpx.AsyncClient, pkg: str) -> dict | None:
    """Fetch full package metadata from the npm registry."""
    try:
        resp = await client.get(f"https://registry.npmjs.org/{pkg}", timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def _published_at(meta: dict, version: str) -> datetime | None:
    """Return the UTC publish time for a specific version."""
    time_data = meta.get("time", {})
    ts = time_data.get(version)
    if ts:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            pass
    return None


def _maintainer_email_changed(meta: dict, version: str) -> bool:
    """Detect if the publisher email changed between the previous and current version."""
    versions = list(meta.get("time", {}).keys())
    # Filter out non-version keys like 'created' / 'modified'
    semver_versions = [v for v in versions if v[0].isdigit()]
    try:
        idx = semver_versions.index(version)
    except ValueError:
        return False

    if idx == 0:
        return False  # first version ever — nothing to compare

    prev_version = semver_versions[idx - 1]
    curr_pub = meta.get("versions", {}).get(version, {}).get("_npmUser", {})
    prev_pub = meta.get("versions", {}).get(prev_version, {}).get("_npmUser", {})

    curr_email = curr_pub.get("email", "")
    prev_email = prev_pub.get("email", "")

    return bool(curr_email and prev_email and curr_email != prev_email)


def _has_slsa_provenance(meta: dict, version: str) -> bool:
    """Check for SLSA provenance metadata on a specific version."""
    ver_data = meta.get("versions", {}).get(version, {})
    dist = ver_data.get("dist", {})
    # npm attaches provenance under dist.attestations or dist.signatures
    return bool(dist.get("attestations") or dist.get("signatures"))


# ---------------------------------------------------------------------------
# Per-file scanners
# ---------------------------------------------------------------------------
async def _scan_package_json(
    path: Path, client: httpx.AsyncClient, known_bad: list[dict] | None = None
) -> list[dict]:
    """Scan a package.json for floating pins, known-bad deps, and lifecycle scripts."""
    if known_bad is None:
        known_bad = KNOWN_BAD
    findings: list[dict] = []
    try:
        data = json.loads(path.read_text())
    except Exception:
        return findings

    # Check lifecycle scripts
    scripts = data.get("scripts", {})
    flagged = {k: v for k, v in scripts.items() if k in LIFECYCLE_SCRIPTS}
    if flagged:
        for script_name, script_cmd in flagged.items():
            findings.append(_finding(
                severity="high",
                title=f"Lifecycle script detected: {script_name}",
                description=(
                    f"The package defines a `{script_name}` script: `{script_cmd}`. "
                    "Lifecycle scripts run automatically on install and are a common "
                    "vector for supply chain attacks (e.g. the March 2026 axios compromise)."
                ),
                file=str(path),
                remediation="Audit this script carefully. If it is not required, remove it. "
                            "Use `npm install --ignore-scripts` to prevent execution.",
                references=["https://docs.npmjs.com/cli/v10/using-npm/scripts"],
            ))

    # Scan all dependency sections
    dep_sections = {
        **data.get("dependencies", {}),
        **data.get("devDependencies", {}),
        **data.get("peerDependencies", {}),
    }

    for pkg, version_spec in dep_sections.items():
        # Floating pin check
        if isinstance(version_spec, str) and (
            version_spec.startswith("^") or version_spec.startswith("~")
        ):
            findings.append(_finding(
                severity="low",
                title=f"Floating version pin: {pkg}@{version_spec}",
                description=(
                    f"`{pkg}` is pinned with `{version_spec[0]}` which allows automatic "
                    "minor/patch upgrades. A hijacked patch release can silently introduce malware."
                ),
                file=str(path),
                remediation=f"Pin to an exact version, e.g. `{pkg}: \"{version_spec[1:]}\"`. "
                            "Use a lockfile and audit upgrades explicitly.",
            ))

        # Known-bad version check (strip leading ^~/= for comparison)
        resolved = version_spec.lstrip("^~=>< ")
        for bad in known_bad:
            if bad["name"] == pkg and bad["version"] == resolved:
                findings.append(_finding(
                    severity="critical",
                    title=f"Known-malicious package: {pkg}@{resolved}",
                    description=(
                        f"`{pkg}@{resolved}` is on the known-bad blocklist. "
                        f"Reason: {bad['reason']}"
                    ),
                    file=str(path),
                    remediation=f"Remove `{pkg}@{resolved}` immediately. "
                                f"Downgrade to the last safe version (e.g. axios@1.14.0). "
                                "Rotate all secrets on affected machines — this version "
                                "installs a remote access trojan.",
                    references=[
                        "https://github.com/advisories",
                        "https://socket.dev",
                    ],
                ))

    return findings


async def _scan_package_lock(
    path: Path, client: httpx.AsyncClient, known_bad: list[dict] | None = None
) -> list[dict]:
    """Scan package-lock.json for resolved known-bad versions and registry anomalies."""
    if known_bad is None:
        known_bad = KNOWN_BAD
    findings: list[dict] = []
    try:
        data = json.loads(path.read_text())
    except Exception:
        return findings

    packages = data.get("packages", {}) or {}

    for pkg_path, pkg_data in packages.items():
        if not pkg_path.startswith("node_modules/"):
            continue
        pkg_name = pkg_path.removeprefix("node_modules/")
        resolved_version = pkg_data.get("version", "")

        # Known-bad check
        for bad in known_bad:
            if bad["name"] == pkg_name and bad["version"] == resolved_version:
                findings.append(_finding(
                    severity="critical",
                    title=f"Known-malicious resolved version: {pkg_name}@{resolved_version}",
                    description=(
                        f"Your lockfile has resolved `{pkg_name}` to `{resolved_version}`, "
                        f"which is on the known-bad blocklist. Reason: {bad['reason']}"
                    ),
                    file=str(path),
                    remediation=f"Run `npm install {pkg_name}@<safe_version>` and commit the updated lockfile. "
                                "Rotate all secrets — this version installs a remote access trojan.",
                    references=["https://socket.dev"],
                ))

        # Registry anomaly checks via npm API
        if resolved_version and pkg_name and not pkg_name.startswith("@"):
            meta = await _fetch_npm_metadata(client, pkg_name)
            if meta:
                # Maintainer email change
                if _maintainer_email_changed(meta, resolved_version):
                    findings.append(_finding(
                        severity="high",
                        title=f"Maintainer email changed at {pkg_name}@{resolved_version}",
                        description=(
                            f"The npm publisher email for `{pkg_name}` changed between "
                            f"the previous version and `{resolved_version}`. This is a "
                            "strong signal of account hijack (as seen in the March 2026 axios attack)."
                        ),
                        file=str(path),
                        remediation="Pin to the last version published by the original maintainer "
                                    "and open an issue with the package maintainers to verify.",
                        references=["https://blog.npmjs.org/post/security"],
                    ))

                # Cooldown gate — recently published
                pub_time = _published_at(meta, resolved_version)
                if pub_time:
                    age = datetime.now(timezone.utc) - pub_time
                    if age < timedelta(hours=COOLDOWN_HOURS):
                        hours_old = int(age.total_seconds() / 3600)
                        findings.append(_finding(
                            severity="medium",
                            title=f"Recently published version: {pkg_name}@{resolved_version} ({hours_old}h ago)",
                            description=(
                                f"`{pkg_name}@{resolved_version}` was published only {hours_old} hours ago, "
                                f"within the {COOLDOWN_HOURS}h cooldown window. New versions have not yet "
                                "been audited by the community and carry elevated supply chain risk."
                            ),
                            file=str(path),
                            remediation=f"Wait {COOLDOWN_HOURS - hours_old}h before adopting this version, "
                                        "or pin to the previous stable release.",
                        ))

                # SLSA provenance
                if not _has_slsa_provenance(meta, resolved_version):
                    findings.append(_finding(
                        severity="info",
                        title=f"No SLSA provenance: {pkg_name}@{resolved_version}",
                        description=(
                            f"`{pkg_name}@{resolved_version}` was not published with SLSA provenance "
                            "metadata, meaning there is no cryptographic link between the npm artifact "
                            "and a verified CI/CD build."
                        ),
                        file=str(path),
                        remediation="Prefer packages published via npm trusted publishing (OIDC). "
                                    "Check https://provenance.npmjs.com for provenance attestations.",
                        references=["https://docs.npmjs.com/generating-provenance-statements"],
                    ))

    return findings


async def _scan_requirements_txt(path: Path) -> list[dict]:
    """Scan requirements.txt for unpinned Python deps and known-bad packages."""
    findings: list[dict] = []
    try:
        lines = path.read_text().splitlines()
    except Exception:
        return findings

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Unpinned if no == constraint
        if "==" not in line and not line.startswith("-"):
            findings.append(_finding(
                severity="low",
                title=f"Unpinned Python dependency: {line}",
                description=(
                    f"`{line}` has no exact version pin. Unpinned deps resolve to "
                    "the latest version at install time, which may pull in a compromised release."
                ),
                file=str(path),
                remediation=f"Pin to an exact version: `{line}==<version>`. "
                            "Use `pip freeze > requirements.txt` to capture current versions.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
async def scan(project_path: str) -> list[dict]:
    """Scan a project directory for supply chain vulnerabilities.

    Checks package.json, package-lock.json, and requirements.txt for:
    - Known-bad versions (axios RAT etc.)
    - Floating/unpinned version specs
    - Lifecycle script injection
    - Maintainer email changes (account hijack signal)
    - Recently published versions (cooldown gate)
    - Missing SLSA provenance

    Returns a list of finding dicts conforming to schemas/finding.json.
    """
    root = Path(project_path)
    findings: list[dict] = []

    # Collect packages for live feed lookup
    npm_packages: list[dict] = []
    pip_packages: list[dict] = []

    pkg_json_path = root / "package.json"
    if pkg_json_path.exists():
        try:
            pkg_data = json.loads(pkg_json_path.read_text())
            deps = {
                **pkg_data.get("dependencies", {}),
                **pkg_data.get("devDependencies", {}),
            }
            for name, ver_spec in deps.items():
                version = ver_spec.lstrip("^~=>< ")
                if version:
                    npm_packages.append({"name": name, "version": version})
        except Exception:
            pass

    req_txt_path = root / "requirements.txt"
    if req_txt_path.exists():
        try:
            for line in req_txt_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "==" not in line:
                    continue
                name, version = line.split("==", 1)
                pip_packages.append({"name": name.strip(), "version": version.strip()})
        except Exception:
            pass

    # Refresh live threat feeds (respects 24h TTL inside fetch_all_feeds)
    if npm_packages or pip_packages:
        try:
            from .threat_feeds import fetch_all_feeds
            from .threat_cache import load_cached_threats, save_threats, get_last_fetch_time
            from datetime import timedelta

            last_fetch = await get_last_fetch_time()
            cache_stale = (
                last_fetch is None
                or (datetime.now(timezone.utc) - last_fetch) > timedelta(hours=24)
            )
            if cache_stale:
                fresh = await fetch_all_feeds(npm_packages, pip_packages)
                if fresh:
                    await save_threats(fresh)
        except Exception:
            pass  # never block a scan

    known_bad = await _get_known_bad()

    async with httpx.AsyncClient() as client:
        tasks = []

        if pkg_json_path.exists():
            tasks.append(_scan_package_json(pkg_json_path, client, known_bad))

        pkg_lock = root / "package-lock.json"
        if pkg_lock.exists():
            tasks.append(_scan_package_lock(pkg_lock, client, known_bad))

        if req_txt_path.exists():
            tasks.append(_scan_requirements_txt(req_txt_path))

        results = await asyncio.gather(*tasks)
        for result in results:
            findings.extend(result)

    return findings
