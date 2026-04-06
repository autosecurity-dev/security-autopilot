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


async def _run_scan(project_path: str) -> None:
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
    shown = ordered[:8]  # cap at 8 for readability
    for f in shown:
        _print_finding(f)

    if len(findings) > 8:
        print(f"\n  {DIM}… and {len(findings) - 8} more. Run with --all to see everything.{RESET}")

    print(f"\n{_BAR}")

    # Auto-patch prompt for critical findings
    critical_findings = [f for f in findings if f["severity"] == "critical"
                         and f.get("scanner") == "supply_chain"]
    if critical_findings:
        print(f"\n{BOLD}🔧 Auto-patching critical supply chain issues…{RESET}\n")
        from mcp_server.tools.autopatch import auto_patch
        for f in critical_findings[:3]:
            result = await auto_patch(str(path), f)
            if result and result.get("success"):
                print(f"  {GREEN}{BOLD}✅  {result['package']} {result['from']} → {result['to']}{RESET}")
            elif result:
                print(f"  {YELLOW}⚠️   {result['package']}: safe version found ({result.get('to','?')}) — run `npm install {result['package']}@{result.get('to','?')}` to apply{RESET}")
            else:
                print(f"  {DIM}↳ {f['title'][:60]} — patch not available{RESET}")

    print()


def run_scan_command(args: list[str]) -> None:
    """Entry point from server.py:main() when sys.argv[1] == 'scan'."""
    if not args or args[0] in ("-h", "--help"):
        print("Usage: security-autopilot scan <path>")
        print("       security-autopilot scan .            # scan current directory")
        sys.exit(0)

    project_path = args[0]
    asyncio.run(_run_scan(project_path))
