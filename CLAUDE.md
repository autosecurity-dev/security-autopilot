# Security Autopilot

MCP server that gives Claude Code native security scanning via Trivy, Gitleaks, Semgrep, and a custom supply chain checker.

## Commands

```bash
uv run pytest tests/ -v          # run all tests
python -m mcp_server.server      # start MCP server
```

## Project layout

```
mcp_server/tools/
  supply_chain.py  ← core: known-bad versions, lifecycle scripts, maintainer hijacks
  trivy.py         ← CVE scanning (requires trivy CLI)
  gitleaks.py      ← secret detection (requires gitleaks CLI)
  semgrep.py       ← SAST (requires semgrep CLI)
  scan_repo.py     ← orchestrates all 4 in parallel via asyncio.gather
mcp_server/aggregator.py         ← SQLite cache at ~/.security-autopilot/findings.db
mcp_server/server.py             ← MCP tool definitions
daemon/watcher.py                ← watchdog daemon, desktop notifications
daemon/scheduler.py              ← auto-detects new projects in ~/projects etc.
```

## Adding a new scanner

1. Create `mcp_server/tools/my_scanner.py`
2. Implement `async def scan(project_path: str) -> list[dict]`
3. Each finding must match `schemas/finding.json`:
   `{id, scanner, severity, title, description, file, line, remediation, references}`
4. Severity values: `critical | high | medium | low | info`
5. Return an `info` finding (not a crash) if the CLI tool is not installed
6. Add to `_SCANNER_MAP` in `scan_repo.py`
7. Add tests in `tests/`

## Unified finding schema

See `schemas/finding.json`. Required fields: `id, scanner, severity, title, description, remediation`.

## Known-bad versions list

`mcp_server/tools/supply_chain.py` → `KNOWN_BAD` list at the top of the file.
Add entries as: `{"name": "pkg", "version": "x.y.z", "reason": "..."}`.
