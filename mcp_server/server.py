"""Security Autopilot MCP Server.

Exposes security scanning tools to Claude Code via the MCP protocol.
Connect via ~/.claude/claude.json — see README for setup instructions.
"""
from __future__ import annotations

import asyncio
from typing import Any

import mcp.server.stdio
import mcp.types as types
from mcp.server import Server

from .tools.scan_repo import scan_repo, scan_file
from .aggregator import get_findings, store
from .telemetry import check_and_ping
from daemon.watcher import start_watcher

app = Server("security-autopilot")

# Active watcher tasks keyed by project path
_watchers: dict[str, asyncio.Task] = {}


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    """Advertise available tools to Claude."""
    return [
        types.Tool(
            name="scan_repo",
            description=(
                "Scan a project directory for security vulnerabilities using Trivy, "
                "Gitleaks, Semgrep, and a supply chain checker that detects attacks "
                "like the March 2026 axios npm compromise."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to the project root"},
                    "checks": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["all", "supply_chain", "trivy", "gitleaks", "semgrep"]},
                        "description": "Which scanners to run. Defaults to all.",
                    },
                },
                "required": ["path"],
            },
        ),
        types.Tool(
            name="scan_file",
            description="Scan a single file for security issues.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {"type": "string", "description": "Absolute path to the file"},
                },
                "required": ["filepath"],
            },
        ),
        types.Tool(
            name="get_findings",
            description="Retrieve cached security findings from previous scans.",
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Filter by severity. Omit to return all.",
                    },
                    "project_path": {
                        "type": "string",
                        "description": "Filter to a specific project path.",
                    },
                },
            },
        ),
        types.Tool(
            name="watch_project",
            description=(
                "Start a background daemon that watches a project for file changes "
                "and automatically re-scans when package.json, lockfiles, or "
                "requirements.txt change."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to the project to watch"},
                },
                "required": ["path"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    """Dispatch tool calls from Claude to the appropriate scanner."""
    if name == "scan_repo":
        result = await scan_repo(
            path=arguments["path"],
            checks=arguments.get("checks", ["all"]),
        )
        await store(result["findings"], arguments["path"])
        return [types.TextContent(type="text", text=_format_scan_result(result))]

    if name == "scan_file":
        result = await scan_file(filepath=arguments["filepath"])
        return [types.TextContent(type="text", text=_format_scan_result(result))]

    if name == "get_findings":
        findings = await get_findings(
            severity=arguments.get("severity"),
            project_path=arguments.get("project_path"),
        )
        return [types.TextContent(type="text", text=_format_findings(findings))]

    if name == "watch_project":
        path = arguments["path"]
        if path not in _watchers or _watchers[path].done():
            _watchers[path] = asyncio.create_task(start_watcher(path))
            msg = f"✓ Watching `{path}` for changes. Auto-scan will trigger on manifest file changes."
        else:
            msg = f"Already watching `{path}`."
        return [types.TextContent(type="text", text=msg)]

    raise ValueError(f"Unknown tool: {name}")


def _format_scan_result(result: dict) -> str:
    """Format scan results as readable markdown for Claude."""
    summary = result["summary"]
    findings = result["findings"]
    path = summary.get("scanned_path", "unknown")

    scanners = ", ".join(summary.get("scanners_run", []))
    duration = summary.get("scan_duration_seconds", 0)
    lines = [
        f"## Security Scan: `{path}`",
        f"**Scanners:** {scanners}  |  **Duration:** {duration}s",
        f"**Found:** {len(findings)} issues — "
        f"🔴 {summary['critical']} critical  "
        f"🟠 {summary['high']} high  "
        f"🟡 {summary['medium']} medium  "
        f"🔵 {summary['low']} low  "
        f"⚪ {summary['info']} info",
        "",
    ]

    # Show critical and high first
    for sev in ("critical", "high", "medium", "low", "info"):
        for f in findings:
            if f["severity"] != sev:
                continue
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[sev]
            lines.append(f"### {emoji} [{sev.upper()}] {f['title']}")
            if f.get("file"):
                loc = f"{f['file']}" + (f":{f['line']}" if f.get("line") else "")
                lines.append(f"**Location:** `{loc}`")
            lines.append(f"**Scanner:** {f['scanner']}")
            lines.append(f"\n{f['description']}")
            lines.append(f"\n**Remediation:** {f['remediation']}")
            if f.get("references"):
                lines.append("**References:** " + " | ".join(f["references"]))
            lines.append("")

    return "\n".join(lines)


def _format_findings(findings: list[dict]) -> str:
    """Format cached findings as readable markdown."""
    if not findings:
        return "No findings in cache. Run `scan_repo` first."
    lines = [f"## Cached Findings ({len(findings)} total)\n"]
    for f in findings:
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(f["severity"], "⚪")
        lines.append(f"{emoji} **{f['title']}** ({f['scanner']}) — {f.get('project_path', '')}")
    return "\n".join(lines)


def main() -> None:
    """Entry point for `uvx security-autopilot`."""
    import sys
    check_and_ping()
    print(
        "Security Autopilot MCP server running.\n"
        "Registered tools: scan_repo, scan_file, get_findings, watch_project",
        file=sys.stderr,
    )
    asyncio.run(mcp.server.stdio.run(app))


if __name__ == "__main__":
    main()
