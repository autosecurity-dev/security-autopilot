"""Pretty-printing CLI wrapper for `security-autopilot scan <path>`.

Called from mcp_server/server.py:main() when sys.argv[1] == "scan".
Runs all scanners and prints a human-readable, coloured report to stdout.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

_SEVERITY_COLOR = {
    "critical": f"{BOLD}{RED}",
    "high":     f"{BOLD}{YELLOW}",
    "medium":   YELLOW,
    "low":      BLUE,
    "info":     DIM,
}

_SEVERITY_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

_BAR = "─" * 64


def _print_finding(f: dict) -> None:
    sev   = f["severity"]
    color = _SEVERITY_COLOR.get(sev, "")
    icon  = _SEVERITY_ICON.get(sev, "")
    print(f"\n{color}{icon} [{sev.upper()}]{RESET} {BOLD}{f['title']}{RESET}")
    desc = f.get("description", "")
    if len(desc) > 140:
        desc = desc[:140] + "…"
    print(f"  {DIM}{desc}{RESET}")
    if f.get("file"):
        rel = f["file"]
        print(f"  {DIM}↳ {rel}{RESET}")
    rem = f.get("remediation", "")
    if rem:
        first_line = rem.splitlines()[0]
        print(f"  {CYAN}Fix: {first_line}{RESET}")


async def _run_scan(project_path: str, yes_flag: bool = False, show_all: bool = False) -> None:
    path = Path(project_path).resolve()
    if not path.exists():
        print(f"{RED}Error: path does not exist: {path}{RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║            🛡️  Security Autopilot — Scanning                 ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}")
    print(f"\n  {DIM}Path: {path}{RESET}\n")

    # Show scanners starting
    scanners = ["supply_chain", "gitleaks", "trivy", "semgrep"]
    for s in scanners:
        print(f"  {DIM}▸ {s}…{RESET}")

    print()

    # Run the full scan
    from mcp_server.tools.scan_repo import scan_repo
    result = await scan_repo(str(path), checks=["all"])
    findings = result.get("findings", [])
    summary  = result.get("summary", {})

    n_critical = summary.get("critical", 0)
    n_high     = summary.get("high", 0)
    n_medium   = summary.get("medium", 0)
    n_low      = summary.get("low", 0)
    n_total    = len(findings)

    # Summary line
    if n_total == 0:
        print(f"  {GREEN}{BOLD}✅  All clear — no issues found.{RESET}\n")
        return

    parts = []
    if n_critical: parts.append(f"{RED}{BOLD}{n_critical} critical{RESET}")
    if n_high:     parts.append(f"{YELLOW}{BOLD}{n_high} high{RESET}")
    if n_medium:   parts.append(f"{YELLOW}{n_medium} medium{RESET}")
    if n_low:      parts.append(f"{BLUE}{n_low} low{RESET}")
    print(f"  {BOLD}Found {n_total} issue(s): {', '.join(parts)}{RESET}")
    print(f"\n{_BAR}")

    # Print findings — critical and high first, then the rest
    ordered = sorted(
        findings,
        key=lambda f: ["critical","high","medium","low","info"].index(f.get("severity","info"))
    )
    shown = ordered if show_all else ordered[:8]
    for f in shown:
        _print_finding(f)

    if not show_all and len(findings) > 8:
        print(f"\n  {DIM}… and {len(findings) - 8} more. Run with --all to see everything.{RESET}")

    print(f"\n{_BAR}")

    # Auto-patch prompt for critical supply chain findings
    critical_findings = [f for f in findings if f["severity"] == "critical"
                         and f.get("scanner") == "supply_chain"]
    if critical_findings:
        from mcp_server.tools.autopatch import auto_patch
        for f in critical_findings[:3]:
            pkg_label = f["title"].replace("Known-malicious package: ", "")
            if yes_flag:
                do_patch = True
            else:
                try:
                    answer = input(f"\n{BOLD}🔧 Auto-patch {RED}{pkg_label}{RESET}{BOLD}? [y/N]{RESET} ").strip().lower()
                    do_patch = answer in ("y", "yes")
                except (EOFError, KeyboardInterrupt):
                    do_patch = False

            if do_patch:
                patch_result = await auto_patch(str(path), f)
                if patch_result and patch_result.get("success"):
                    print(f"  {GREEN}{BOLD}✅  {patch_result['package']} {patch_result['from']} → {patch_result['to']}{RESET}")
                elif patch_result:
                    print(f"  {YELLOW}⚠️   Safe version found ({patch_result.get('to','?')}) — run: npm install {patch_result['package']}@{patch_result.get('to','?')}{RESET}")
                else:
                    print(f"  {DIM}↳ patch not available for {f['title'][:60]}{RESET}")
            else:
                print(f"  {DIM}↳ skipped — run with --yes to auto-apply{RESET}")

    print()


def run_scan_command(args: list[str]) -> None:
    """Entry point from server.py:main() when sys.argv[1] == 'scan'."""
    if not args or args[0] in ("-h", "--help"):
        print("Usage: security-autopilot scan <path> [--yes] [--all]")
        print("       security-autopilot scan .            # scan current directory")
        print("       security-autopilot scan . --yes      # auto-apply all patches (CI mode)")
        print("       security-autopilot scan . --all      # show every finding, no cap")
        sys.exit(0)

    yes_flag = "--yes" in args
    show_all = "--all" in args
    path_args = [a for a in args if not a.startswith("--")]
    project_path = path_args[0] if path_args else "."
    asyncio.run(_run_scan(project_path, yes_flag=yes_flag, show_all=show_all))
