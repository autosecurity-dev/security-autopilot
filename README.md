<div align="center">

# 🛡️ Security Autopilot

### The security scanner that works *while you code* — not after you ship.

[![Tests](https://img.shields.io/badge/tests-10%20passing-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-compatible-purple)](https://modelcontextprotocol.io)

</div>

---

## The Problem

On **March 30, 2026**, two malicious versions of `axios` — one of the most downloaded npm packages on the planet — were quietly published to npm.

They contained **zero suspicious code inside axios itself**. Any developer who inspected the source would have found nothing wrong.

Instead, they silently injected a fake dependency called `plain-crypto-js` that ran a **postinstall script the moment you ran `npm install`**. That script phoned home to a command-and-control server and dropped a remote access trojan tailored to your OS.

After delivering the payload, it deleted itself and swapped its own `package.json` for a clean decoy. **No trace. No warning. No audit trail.**

`npm audit` reported nothing. GitHub Dependabot reported nothing. Standard code review caught nothing.

> **This is the new shape of supply chain attacks** — and your existing tools aren't built to catch them.

---

## What Security Autopilot Does

Security Autopilot is an **MCP server** that plugs directly into Claude Code and gives it real security scanning superpowers. You talk to Claude naturally — it runs the scans.

It catches the class of attacks that traditional tools miss:

| What it catches | How it catches it |
|---|---|
| 🔴 **Known-malicious packages** (axios@1.14.1, plain-crypto-js@4.2.1) | Blocklist checked before any install |
| 🟠 **Maintainer account hijacks** | Detects publisher email changes between versions |
| 🟠 **Postinstall script injection** | Flags any `preinstall`, `install`, `postinstall`, `prepare` lifecycle scripts |
| 🟡 **Recently published versions** | 72-hour cooldown gate on new releases |
| 🔵 **Floating version pins** | Flags `^` and `~` pins that allow silent upgrades |
| 🔵 **Missing SLSA provenance** | Detects packages published without cryptographic build attestations |
| 🟠 **Exposed secrets & credentials** | Gitleaks scans every file for hardcoded API keys, tokens, passwords |
| 🟡 **CVEs in your dependencies** | Trivy scans against the full NVD vulnerability database |
| 🟡 **Code-level security bugs** | Semgrep catches `eval(userInput)`, SQL injection, XSS, and 1000+ other patterns |

---

## How It Works

```
You type:  "is my supply chain safe?"
              │
              ▼
        Claude Code calls scan_repo()
              │
    ┌─────────┴──────────┐
    │   4 scanners run   │  ← all in parallel, ~10 seconds total
    │   simultaneously   │
    └─────────┬──────────┘
              │
    ┌─────────┴────────────────────────────────────┐
    │  Supply Chain  │  Trivy  │  Gitleaks  │  Semgrep  │
    └─────────┬────────────────────────────────────┘
              │
              ▼
    Claude summarises findings in plain English
    with severity, location, and exact fix steps
```

Missing a scanner? **Security Autopilot installs it for you automatically** — no setup required.

---

## Quick Start

### 1. Install (one command)

```bash
curl -fsSL https://get.securityautopilot.dev | sh
```

This installs `uv`, the MCP server, all scanner CLIs (trivy, gitleaks, semgrep), and automatically patches `~/.claude/claude.json` to register the plugin. Safe to run twice.

> **Telemetry:** On first run you'll be asked whether to share anonymous usage data (OS + Python version). You can opt out at any time by deleting `~/.security-autopilot/telemetry_consent`.

### 2. Restart Claude Code

That's it — no manual config needed.

### 3. Just talk to Claude

```
"scan this project for security issues"
"any secrets exposed in this codebase?"
"is my supply chain safe?"
"check my dependencies for known vulnerabilities"
"watch this project and alert me to new issues"
```

---

## What a Scan Looks Like

```
## Security Scan: `/your/project`
Scanners: supply_chain, trivy, gitleaks, semgrep  |  Duration: 8.3s
Found: 4 issues — 🔴 1 critical  🟠 2 high  🟡 0 medium  🔵 1 low

### 🔴 [CRITICAL] Known-malicious package: axios@1.14.1
Location: package.json
Scanner: supply_chain

axios@1.14.1 is on the known-bad blocklist.
Reason: supply chain RAT March 2026 — postinstall dropper

Remediation: Remove axios@1.14.1 immediately. Downgrade to axios@1.14.0.
Rotate all secrets on affected machines — this version installs a
remote access trojan.

### 🟠 [HIGH] Exposed aws-secret-access-key secret in .env
Location: .env:3
Scanner: gitleaks

Rotate this credential immediately — assume it is compromised.
Add `.env` to .gitignore to prevent future commits.
```

---

## MCP Tools

Claude gets access to 4 tools automatically:

| Tool | What it does |
|---|---|
| `scan_repo(path)` | Full scan — all 4 scanners in parallel |
| `scan_file(filepath)` | Scan a single file |
| `get_findings(severity)` | Retrieve cached findings from previous scans |
| `watch_project(path)` | Start a background daemon that re-scans on file changes |

The background watcher also sends a **desktop notification** the moment a new critical or high finding is detected — even if Claude Code isn't open.

---

## Scanners

| Scanner | What it catches | Auto-installed? |
|---|---|---|
| **Supply Chain** | Known-bad versions, account hijacks, lifecycle scripts, floating pins, SLSA gaps | ✅ Built-in |
| **Trivy** | CVEs in npm, pip, Go, Rust, Java dependencies | ✅ Auto-installed |
| **Gitleaks** | Hardcoded secrets, API keys, tokens, passwords | ✅ Auto-installed |
| **Semgrep** | 1000+ SAST rules: injection, XSS, insecure patterns | ✅ Auto-installed |

---

## For Contributors

```bash
# Run tests
uv run pytest tests/ -v

# Start the MCP server manually
python -m mcp_server.server

# Add a new scanner
# → see CLAUDE.md for the exact pattern to follow
```

### Adding a scanner takes ~50 lines

Every scanner follows the same pattern:

```python
# mcp_server/tools/my_scanner.py
from .installer import ensure_installed

async def scan(project_path: str) -> list[dict]:
    if not await ensure_installed("my-tool"):
        return [_not_installed_finding()]
    # ... run subprocess, parse output, return findings
```

See `schemas/finding.json` for the unified finding schema all scanners must conform to.

---

## Known-Bad Versions

The supply chain scanner ships with a blocklist that is updated as attacks are discovered:

```python
# mcp_server/tools/supply_chain.py → KNOWN_BAD
[
  {"name": "axios",           "version": "1.14.1", "reason": "supply chain RAT March 2026"},
  {"name": "axios",           "version": "0.30.4", "reason": "supply chain RAT March 2026"},
  {"name": "plain-crypto-js", "version": "4.2.1",  "reason": "axios attack dropper"},
]
```

PRs to extend this list are welcome.

---

## License

MIT — free to use, modify, and distribute.

---

<div align="center">

Built in response to the **March 2026 axios supply chain attack**.  
Because `npm audit` wasn't enough.

</div>
