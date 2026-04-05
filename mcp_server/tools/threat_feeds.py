"""Live threat feed fetcher.

Pulls known-malicious package data from:
- OSV.dev (Google) — covers npm, pip, Go, Rust, Maven
- npm audit API  — npm's own supply-chain advisory endpoint

All sources are free, require no API key, and are fetched concurrently.
Results are merged, deduplicated, and returned in KNOWN_BAD format.
Falls back to empty list on any network/parse error — never blocks a scan.
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger(__name__)

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_NPM_ADVISORY_URL = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"
_TIMEOUT = 10


# ── OSV.dev ───────────────────────────────────────────────────────────────────

async def fetch_osv(packages: list[dict]) -> list[dict]:
    """Query OSV for vulnerabilities in the given packages.

    Args:
        packages: list of {"name": str, "version": str, "ecosystem": "npm"|"PyPI"|...}

    Returns:
        list of KNOWN_BAD-format dicts with source="osv"
    """
    if not packages:
        return []

    queries = [
        {
            "package": {"name": p["name"], "ecosystem": p.get("ecosystem", "npm")},
            "version": p["version"],
        }
        for p in packages
    ]
    payload = json.dumps({"queries": queries}).encode()

    try:
        data = await _post(_OSV_BATCH_URL, payload)
    except Exception as exc:
        log.debug("OSV fetch failed: %s", exc)
        return []

    results = []
    for pkg, response in zip(packages, data.get("results", [])):
        for vuln in response.get("vulns", []):
            severity = _osv_severity(vuln)
            if severity not in ("CRITICAL", "HIGH"):
                continue
            reason = vuln.get("summary") or vuln.get("id", "vulnerability")
            results.append({
                "name": pkg["name"],
                "version": pkg["version"],
                "reason": f"{reason} [{vuln.get('id', '')}]",
                "source": "osv",
            })

    log.debug("OSV returned %d threats for %d packages", len(results), len(packages))
    return results


def _osv_severity(vuln: dict) -> str:
    """Extract the highest severity from an OSV vulnerability object."""
    for severity in vuln.get("severity", []):
        score = severity.get("score", "")
        if "CRITICAL" in score.upper():
            return "CRITICAL"
        if "HIGH" in score.upper():
            return "HIGH"
    # Fall back to database-specific severity
    for affected in vuln.get("affected", []):
        for sev in affected.get("severity", []):
            rating = sev.get("rating", "").upper()
            if rating in ("CRITICAL", "HIGH"):
                return rating
    return "UNKNOWN"


# ── npm audit API ─────────────────────────────────────────────────────────────

async def fetch_npm_advisories(packages: list[dict]) -> list[dict]:
    """Query npm's security advisory bulk endpoint.

    Args:
        packages: list of {"name": str, "version": str}

    Returns:
        list of KNOWN_BAD-format dicts with source="npm"
    """
    if not packages:
        return []

    # Build {name: [versions]} map
    bulk: dict[str, list[str]] = {}
    for p in packages:
        bulk.setdefault(p["name"], []).append(p["version"])

    payload = json.dumps(bulk).encode()

    try:
        data = await _post(_NPM_ADVISORY_URL, payload)
    except Exception as exc:
        log.debug("npm advisory fetch failed: %s", exc)
        return []

    results = []
    for pkg_name, advisories in data.items():
        for advisory in advisories:
            severity = advisory.get("severity", "").upper()
            if severity not in ("CRITICAL", "HIGH"):
                continue
            title = advisory.get("title", "vulnerability")
            # Match affected versions
            for version in bulk.get(pkg_name, []):
                results.append({
                    "name": pkg_name,
                    "version": version,
                    "reason": f"{title} (npm advisory #{advisory.get('id', '')})",
                    "source": "npm",
                })

    log.debug("npm advisories returned %d threats", len(results))
    return results


# ── Combined fetch ────────────────────────────────────────────────────────────

async def fetch_all_feeds(
    npm_packages: list[dict],
    pip_packages: list[dict],
) -> list[dict]:
    """Fetch from all sources concurrently and return deduplicated results.

    Args:
        npm_packages: list of {"name": str, "version": str}
        pip_packages: list of {"name": str, "version": str}

    Returns:
        Deduplicated list in KNOWN_BAD format (name, version, reason, source)
    """
    osv_npm = [dict(p, ecosystem="npm") for p in npm_packages]
    osv_pip = [dict(p, ecosystem="PyPI") for p in pip_packages]

    osv_results, npm_results = await asyncio.gather(
        fetch_osv(osv_npm + osv_pip),
        fetch_npm_advisories(npm_packages),
        return_exceptions=False,
    )

    # Deduplicate by (name, version) — keep first seen
    seen: set[tuple[str, str]] = set()
    merged = []
    for entry in [*osv_results, *npm_results]:
        key = (entry["name"], entry["version"])
        if key not in seen:
            seen.add(key)
            merged.append(entry)

    log.info("Threat feeds: %d unique threats from %d npm + %d pip packages",
             len(merged), len(npm_packages), len(pip_packages))
    return merged


# ── HTTP helper ───────────────────────────────────────────────────────────────

async def _post(url: str, payload: bytes) -> Any:
    """Async POST using stdlib urllib in a thread pool."""
    def _do_post() -> Any:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read())

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _do_post)
