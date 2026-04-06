# Security Autopilot

MCP server that gives Claude Code native security scanning by wrapping four
tools — Trivy, Gitleaks, Semgrep, and a custom supply chain checker — and
exposing them as MCP tools. Users install via a one-liner (`install.sh`);
Claude Code then calls `scan_repo`, `scan_file`, `get_findings`, or
`watch_project` directly from the chat prompt.

---

## Commands

```bash
uv run pytest tests/ -v                    # run all tests (23 total)
python -m mcp_server.server --version      # print version and exit
python -m mcp_server.server                # start MCP server (stdio)
uv tool install security-autopilot         # install as CLI tool
```

---

## File map (every file, one line)

```
install.sh                          one-liner installer (https://raw.githubusercontent.com/autosecurity-dev/security-autopilot/main/install.sh)
docs/index.html                     minimal dark landing page (pure HTML, no framework)
schemas/finding.json                JSON Schema for a single finding — all scanners must conform
pyproject.toml                      package config; entry point: mcp_server.server:main

mcp_server/server.py                MCP tool definitions + dispatch; calls telemetry on startup
mcp_server/aggregator.py            SQLite cache at ~/.security-autopilot/findings.db
mcp_server/telemetry.py             opt-in anonymous usage pings via PostHog HTTP API (stdlib only)
mcp_server/__main__.py              allows `python -m mcp_server.server`

mcp_server/tools/scan_repo.py       orchestrates all 4 scanners in parallel via asyncio.gather
mcp_server/tools/supply_chain.py    core scanner: KNOWN_BAD list, lifecycle scripts, maintainer hijacks
mcp_server/tools/trivy.py           CVE scanner — shells out to trivy CLI
mcp_server/tools/gitleaks.py        secret detection — shells out to gitleaks CLI
mcp_server/tools/semgrep.py         SAST — shells out to semgrep CLI
mcp_server/tools/installer.py       auto-installs trivy/gitleaks/semgrep if missing (macOS + Linux)

daemon/watcher.py                   watchdog daemon; re-scans on manifest file changes; sends desktop notifications
daemon/scheduler.py                 auto-detects new projects in ~/projects, ~/code, ~/Desktop/projects

tests/test_supply_chain.py          unit tests for supply chain scanner (axios attack fixture)
tests/test_integration.py           integration tests for scan_repo end-to-end
tests/fixtures/axios_attack/        package.json pinned to axios@1.14.1 (known-bad)
```

---

## Unified finding schema

Every scanner must return a `list[dict]` where each dict conforms to
`schemas/finding.json`. Deviations will fail aggregator validation.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "SecurityFinding",
  "type": "object",
  "required": ["id", "scanner", "severity", "title", "description", "remediation"],
  "properties": {
    "id":          { "type": "string", "format": "uuid" },
    "scanner":     { "type": "string", "enum": ["supply_chain", "trivy", "gitleaks", "semgrep"] },
    "severity":    { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
    "title":       { "type": "string" },
    "description": { "type": "string" },
    "file":        { "type": ["string", "null"] },
    "line":        { "type": ["integer", "null"] },
    "remediation": { "type": "string" },
    "references":  { "type": "array", "items": { "type": "string" } }
  }
}
```

**Severity values:** `critical | high | medium | low | info`
**Rule:** if the CLI tool is not installed, return one `info` finding —
never raise an exception.

---

## Known-bad versions list

`mcp_server/tools/supply_chain.py` → `KNOWN_BAD` list at the top of the file.

```python
KNOWN_BAD: list[dict[str, str]] = [
    {"name": "axios",           "version": "1.14.1", "reason": "supply chain RAT March 2026 — postinstall dropper"},
    {"name": "axios",           "version": "0.30.4", "reason": "supply chain RAT March 2026 — postinstall dropper"},
    {"name": "plain-crypto-js", "version": "4.2.1",  "reason": "axios attack dropper — remote access trojan"},
]
```

Add new entries as `{"name": "pkg", "version": "x.y.z", "reason": "..."}`.

---

## Adding a new scanner

1. Create `mcp_server/tools/my_scanner.py`
2. Implement `async def scan(project_path: str) -> list[dict]`
3. Each finding must conform to the schema above
4. Return an `info` finding (not a crash) if the CLI tool is not installed
5. Add to `_SCANNER_MAP` in `scan_repo.py`
6. Register the new scanner name in `schemas/finding.json` → `scanner.enum`
7. Add tests in `tests/`

---

## Context management

- **Compact after major changes** — after completing a major architectural decision, a significant feature, or switching tasks, run `/compact` to compress the conversation context. This keeps token usage efficient and responses sharp.
- **When to compact:** finishing a feature branch, completing a P0/P1 fix batch, switching from coding to debugging, or whenever context hits 60%.

---

## Coding rules

- **Async only** — all scanner functions are `async def`; no blocking I/O on
  the event loop. Shell out with `asyncio.create_subprocess_exec`, not
  `subprocess.run`.
- **Graceful degradation** — a missing CLI tool, network timeout, or parse
  error must never crash the server. Return an `info` finding with a clear
  message; log the exception to stderr.
- **Idempotency** — `install.sh` and the claude.json patch are safe to run
  multiple times without side effects.
- **No new dependencies for telemetry** — `telemetry.py` uses stdlib `urllib`
  only. Do not add the PostHog SDK.
- **Test coverage** — every scanner needs at minimum: (a) a happy-path test
  with a real fixture, (b) a test for the "tool not installed" info-finding
  path. Integration tests live in `test_integration.py`.

---

## Current status

### Built and working
- MCP server with four tools: `scan_repo`, `scan_file`, `get_findings`, `watch_project`
- Supply chain scanner with KNOWN_BAD blocklist, lifecycle script detection, maintainer hijack heuristics
- Trivy, Gitleaks, Semgrep wrappers that shell out to CLI tools
- Auto-installer (`installer.py`) for missing CLI tools — macOS (brew) + Linux (curl)
- SQLite findings cache via `aggregator.py` — findings expire after 7 days, old scan results cleared on rescan
- Background file watcher (`daemon/watcher.py`) + project auto-detector (`daemon/scheduler.py`)
- Auto-patch for known-malicious packages (`autopatch.py`) — semver-safe, same major only
- Loud secret alerts with rotation instructions per service (`secret_remediation.py`)
- Live threat feeds from OSV.dev + npm advisory API (`threat_feeds.py`, `threat_cache.py`) — 24h TTL cache
- Self-updating daemon — checks PyPI on startup and every 24h (`updater.py`)
- `--version` flag on the CLI
- `install.sh` one-liner — repo is public at `autosecurity-dev/security-autopilot`
- `docs/index.html` minimal landing page
- 23 passing tests covering supply chain, axios attack patterns, integration, and critical paths

### PostHog key not yet configured
`mcp_server/telemetry.py` and `docs/index.html` contain `YOUR_POSTHOG_KEY` —
replace with the real `phc_...` key once the account is created.
Telemetry defaults to opted_out; no stdin reads, no prompts.

### Threat detection roadmap
| Phase | What | Status |
|---|---|---|
| 1 | `threats/threats.json` hosted feed — manual entries go live within minutes, no PyPI release needed | Shipped |
| 2 | GitHub Actions watchlist — checks top-60 npm packages every 30 min for suspicious new versions, opens issues for human review | Shipped |
| 3 | Always-on VPS worker — subscribes to npm CouchDB changes feed in real time (~seconds detection lag), requires $6–12/mo server | Planned v3 |

### What's next (P2 — shippable without)
- Set up `autosecurity.dev` domain and point to landing page
- Configure PostHog key in `mcp_server/telemetry.py` and `docs/index.html`
- Linux desktop notifications (currently macOS-only via osascript)
- `install.sh` not yet tested on a clean Ubuntu 22 VM
