#!/usr/bin/env python3
"""Watchlist checker — runs every 30 minutes via GitHub Actions.

Fetches the latest version of each package in threats/watchlist.json from the
npm registry, compares it to the last known version in threats/last-seen.json,
and flags suspicious changes:

  - New lifecycle scripts (postinstall / preinstall / install / prepare)
  - Publisher email change (account hijack signal)
  - Package size jumped more than 3x

When something is flagged, a GitHub issue is opened for human review. If the
finding is confirmed, the entry is manually added to threats/threats.json.

Detection roadmap:
  Phase 1 — threats.json manual feed (shipped): new entries go live within
    minutes of confirmation, no package release needed.
  Phase 2 — this watchlist (shipped): auto-flags suspicious npm publishes
    every 30 min, human reviews before threats.json is updated.
  Phase 3 — always-on VPS worker (planned v3): subscribe to the npm CouchDB
    changes feed in real time (~seconds detection), no 30-min polling gap.
    Requires a $6/mo server and ongoing infra management — justified once
    user count warrants it.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
WATCHLIST_FILE = REPO_ROOT / "threats" / "watchlist.json"
LAST_SEEN_FILE = REPO_ROOT / "threats" / "last-seen.json"
LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}
SIZE_JUMP_THRESHOLD = 3.0  # flag if new version is >3x the size of old version


# ---------------------------------------------------------------------------
# npm registry helpers
# ---------------------------------------------------------------------------

def _fetch(url: str, timeout: int = 10) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception as exc:
        print(f"  [warn] fetch {url}: {exc}", file=sys.stderr)
        return None


def fetch_latest(package: str) -> dict | None:
    """Fetch the metadata for the latest published version of a package."""
    return _fetch(f"https://registry.npmjs.org/{package}/latest")


def fetch_version(package: str, version: str) -> dict | None:
    """Fetch metadata for a specific version."""
    return _fetch(f"https://registry.npmjs.org/{package}/{version}")


# ---------------------------------------------------------------------------
# Heuristic checks
# ---------------------------------------------------------------------------

def check_new_lifecycle_scripts(
    old_meta: dict | None, new_meta: dict
) -> list[str]:
    """Return lifecycle scripts added in new_meta that were absent in old_meta."""
    old_scripts = set((old_meta or {}).get("scripts", {}).keys()) & LIFECYCLE_SCRIPTS
    new_scripts = set(new_meta.get("scripts", {}).keys()) & LIFECYCLE_SCRIPTS
    added = new_scripts - old_scripts
    return sorted(added)


def check_size_jump(old_meta: dict | None, new_meta: dict) -> float | None:
    """Return size ratio if the package grew more than SIZE_JUMP_THRESHOLD, else None."""
    old_size = ((old_meta or {}).get("dist") or {}).get("unpackedSize", 0)
    new_size = (new_meta.get("dist") or {}).get("unpackedSize", 0)
    if old_size and new_size:
        ratio = new_size / old_size
        if ratio > SIZE_JUMP_THRESHOLD:
            return round(ratio, 1)
    return None


def check_publisher_change(old_meta: dict | None, new_meta: dict) -> tuple[str, str] | None:
    """Return (old_email, new_email) if the publisher email changed, else None."""
    old_email = ((old_meta or {}).get("_npmUser") or {}).get("email", "")
    new_email = (new_meta.get("_npmUser") or {}).get("email", "")
    if old_email and new_email and old_email != new_email:
        return old_email, new_email
    return None


# ---------------------------------------------------------------------------
# GitHub issue creation
# ---------------------------------------------------------------------------

def open_github_issue(
    package: str,
    new_version: str,
    old_version: str,
    flags: list[str],
) -> None:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    title = f"[Watchlist] Suspicious new version: {package}@{new_version}"

    body_lines = [
        f"## Watchlist Alert: `{package}@{new_version}`",
        "",
        "The automated watchlist checker flagged this new version.",
        "",
        f"**Previous version:** `{old_version}`  ",
        f"**New version:** `{new_version}`",
        "",
        "**Flags triggered:**",
        *[f"- {f}" for f in flags],
        "",
        "**Next steps:**",
        f"1. Review the package: https://www.npmjs.com/package/{package}/v/{new_version}",
        f"2. Check the diff: https://diff.intrinsic.com/{package}/{old_version}/{new_version}",
        "3. If confirmed malicious → add entry to `threats/threats.json` and close this issue",
        "4. If benign → close this issue with a comment explaining why",
        "",
        f"_Auto-generated at {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}_",
    ]
    body = "\n".join(body_lines)

    if not repo or not token:
        print(f"\n[ALERT] {title}")
        print(body)
        return

    # Check for existing open issue with the same title to avoid duplicates
    search_url = (
        f"https://api.github.com/search/issues"
        f"?q={urllib.parse.quote(title)}+repo:{repo}+is:issue+is:open"
    )
    existing = _github_get(search_url, token)
    if existing and existing.get("total_count", 0) > 0:
        print(f"  [skip] Issue already open for {package}@{new_version}")
        return

    data = json.dumps({
        "title": title,
        "body": body,
        "labels": ["security", "watchlist"],
    }).encode()
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/issues",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            issue = json.loads(resp.read().decode())
            print(f"  [alert] Opened issue #{issue['number']}: {title}")
    except urllib.error.HTTPError as exc:
        print(f"  [error] Could not create issue: {exc} — {exc.read().decode()}", file=sys.stderr)
    except Exception as exc:
        print(f"  [error] Could not create issue: {exc}", file=sys.stderr)


def _github_get(url: str, token: str) -> dict | None:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


# Needed for URL encoding in open_github_issue
import urllib.parse


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    packages: list[str] = json.loads(WATCHLIST_FILE.read_text()).get("packages", [])
    last_seen: dict[str, str] = (
        json.loads(LAST_SEEN_FILE.read_text()) if LAST_SEEN_FILE.exists() else {}
    )

    updated_last_seen = dict(last_seen)
    suspicious: list[tuple[str, str, str, list[str]]] = []  # (pkg, new_ver, old_ver, flags)

    for package in packages:
        print(f"Checking {package}...")
        new_meta = fetch_latest(package)
        if not new_meta:
            continue

        new_version = new_meta.get("version", "")
        if not new_version:
            continue

        old_version = last_seen.get(package, "")
        updated_last_seen[package] = new_version

        # First run — record state, skip analysis (no baseline to compare)
        if not old_version:
            print(f"  [init] recording {package}@{new_version}")
            continue

        # No change
        if old_version == new_version:
            continue

        print(f"  New version: {old_version} → {new_version}")
        old_meta = fetch_version(package, old_version)

        flags: list[str] = []

        added_scripts = check_new_lifecycle_scripts(old_meta, new_meta)
        if added_scripts:
            script_list = ", ".join(f"`{s}`" for s in added_scripts)
            flags.append(f"New lifecycle scripts added: {script_list}")

        ratio = check_size_jump(old_meta, new_meta)
        if ratio is not None:
            flags.append(f"Package size jumped {ratio}x (from {old_version} to {new_version})")

        publisher_change = check_publisher_change(old_meta, new_meta)
        if publisher_change:
            old_email, new_email = publisher_change
            flags.append(f"Publisher email changed: `{old_email}` → `{new_email}`")

        if flags:
            print(f"  [SUSPICIOUS] {len(flags)} flag(s): {'; '.join(flags)}")
            suspicious.append((package, new_version, old_version, flags))
        else:
            print(f"  [ok] {package}@{new_version} — no suspicious patterns")

    # Persist updated last-seen
    LAST_SEEN_FILE.write_text(json.dumps(updated_last_seen, indent=2, sort_keys=True) + "\n")
    print(f"\nChecked {len(packages)} packages. {len(suspicious)} suspicious.")

    for pkg, new_ver, old_ver, flags in suspicious:
        open_github_issue(pkg, new_ver, old_ver, flags)

    return 1 if suspicious else 0


if __name__ == "__main__":
    sys.exit(main())
