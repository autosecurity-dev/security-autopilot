"""First-run experience for `uvx security-autopilot` (no arguments, TTY mode).

Automatically finds dev projects, scans them, and shows results.
No prompts — just works.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# ── ANSI colours (same as scan_ctl) ──────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

_SEVERITY_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

_SEVERITY_COLOR = {
    "critical": f"{BOLD}{RED}",
    "high":     f"{BOLD}{YELLOW}",
    "medium":   YELLOW,
    "low":      BLUE,
    "info":     DIM,
}

# Dev folders to search — ordered by likelihood
_DEV_ROOTS = [
    "Desktop/projects",
    "projects",
    "code",
    "dev",
    "work",
    "src",
    "repos",
    "Developer",
    "Desktop",
]

# A directory is a "project" if it contains any of these
_PROJECT_MARKERS = [
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "composer.json",
]

# Scan at most this many projects per run to stay fast
_MAX_PROJECTS = 6


def _find_projects() -> list[Path]:
    """Return up to _MAX_PROJECTS project directories, most recently modified first."""
    home = Path.home()
    candidates: list[Path] = []
    seen: set[Path] = set()

    for root_name in _DEV_ROOTS:
        root = home / root_name
        if not root.is_dir():
            continue
        # Direct children of the root that look like projects
        for child in root.iterdir():
            if not child.is_dir() or child.name.startswith("."):
                continue
            resolved = child.resolve()
            if resolved in seen:
                continue
            if any((child / marker).exists() for marker in _PROJECT_MARKERS):
                seen.add(resolved)
                candidates.append(child)

    # Also check the home dir itself (e.g. ~/myapp)
    for child in home.iterdir():
        if not child.is_dir() or child.name.startswith("."):
            continue
        resolved = child.resolve()
        if resolved in seen:
            continue
        if any((child / marker).exists() for marker in _PROJECT_MARKERS):
            seen.add(resolved)
            candidates.append(child)

    # Sort by most recently modified, take top N
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[:_MAX_PROJECTS]


def _is_daemon_running() -> bool:
    pid_file = Path.home() / ".security-autopilot" / "daemon.pid"
    if not pid_file.exists():
        return False
    try:
        import os
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _is_claude_plugin_installed() -> bool:
    claude_json = Path.home() / ".claude" / "claude.json"
    if not claude_json.exists():
        return False
    try:
        import json
        data = json.loads(claude_json.read_text())
        mcps = data.get("mcpServers", {})
        return "security-autopilot" in mcps
    except Exception:
        return False


async def _scan_projects(projects: list[Path]) -> list[tuple[Path, dict]]:
    """Scan all projects concurrently, return (path, result) pairs."""
    from mcp_server.tools.scan_repo import scan_repo

    async def _scan_one(path: Path) -> tuple[Path, dict]:
        try:
            result = await scan_repo(str(path), checks=["all"])
            return path, result
        except Exception as exc:
            return path, {"findings": [], "summary": {}, "error": str(exc)}

    results = await asyncio.gather(*[_scan_one(p) for p in projects])
    return list(results)


def _print_project_summary(path: Path, result: dict) -> None:
    findings = result.get("findings", [])
    summary = result.get("summary", {})

    n_critical = summary.get("critical", 0)
    n_high = summary.get("high", 0)
    n_total = len(findings)

    name = path.name
    if n_total == 0:
        print(f"  {GREEN}✓{RESET}  {BOLD}{name}{RESET}  {DIM}— clean{RESET}")
        return

    parts = []
    if n_critical: parts.append(f"{RED}{BOLD}{n_critical} critical{RESET}")
    if n_high:     parts.append(f"{YELLOW}{n_high} high{RESET}")
    rest = n_total - n_critical - n_high
    if rest:       parts.append(f"{DIM}{rest} other{RESET}")

    print(f"  {RED if n_critical else YELLOW}!{RESET}  {BOLD}{name}{RESET}  {', '.join(parts)}")

    # Show critical findings inline
    for f in findings:
        if f["severity"] in ("critical", "high"):
            icon = _SEVERITY_ICON[f["severity"]]
            color = _SEVERITY_COLOR[f["severity"]]
            title = f["title"]
            print(f"      {color}{icon} {title}{RESET}")
            rem = f.get("remediation", "")
            if rem:
                print(f"         {CYAN}{DIM}{rem.splitlines()[0][:80]}{RESET}")


async def run_first_run() -> None:
    """Auto-scan dev projects and show results. Called when no args are given."""
    from importlib.metadata import version as pkg_version, PackageNotFoundError
    try:
        v = pkg_version("security-autopilot")
    except PackageNotFoundError:
        v = "dev"

    print(f"\n{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║          🛡️  Security Autopilot v{v:<28}║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}\n")

    projects = _find_projects()

    if not projects:
        print(f"  {DIM}No projects found in common dev folders.{RESET}")
        print(f"  To scan a specific path: {CYAN}security-autopilot scan <path>{RESET}\n")
        return

    print(f"  {DIM}Found {len(projects)} project(s) — scanning…{RESET}\n")
    for p in projects:
        print(f"  {DIM}▸ {p}{RESET}")
    print()

    results = await _scan_projects(projects)

    # ── Results ───────────────────────────────────────────────────────────────
    total_critical = sum(r.get("summary", {}).get("critical", 0) for _, r in results)
    total_high     = sum(r.get("summary", {}).get("high", 0) for _, r in results)
    total_issues   = sum(len(r.get("findings", [])) for _, r in results)

    print("─" * 64)
    print()
    for path, result in results:
        _print_project_summary(path, result)
    print()
    print("─" * 64)

    if total_issues == 0:
        print(f"\n  {GREEN}{BOLD}✅  All clear — no issues found across {len(projects)} project(s).{RESET}")
    else:
        parts = []
        if total_critical: parts.append(f"{RED}{BOLD}{total_critical} critical{RESET}")
        if total_high:     parts.append(f"{YELLOW}{BOLD}{total_high} high{RESET}")
        other = total_issues - total_critical - total_high
        if other:          parts.append(f"{DIM}{other} other{RESET}")
        print(f"\n  {BOLD}Total: {total_issues} issue(s) across {len(projects)} project(s) — {', '.join(parts)}{RESET}")
        print(f"\n  {DIM}To scan a specific project with auto-fix:{RESET}")
        print(f"  {CYAN}security-autopilot scan <path> --yes{RESET}")

    # ── Setup nudges ──────────────────────────────────────────────────────────
    nudges = []
    if not _is_daemon_running():
        nudges.append(
            f"  {DIM}▸ Start the background daemon (auto-scans on file changes):{RESET}\n"
            f"    {CYAN}security-autopilot daemon start{RESET}"
        )
    if not _is_claude_plugin_installed():
        nudges.append(
            f"  {DIM}▸ Add to Claude Code for in-chat scanning:{RESET}\n"
            f"    {CYAN}security-autopilot install-plugin{RESET}"
        )

    if nudges:
        print(f"\n  {DIM}── Optional setup ─────────────────────────────────────────{RESET}")
        for nudge in nudges:
            print(nudge)

    print()
