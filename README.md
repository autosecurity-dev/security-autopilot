# Security Autopilot

An open-source MCP server that gives Claude Code native security scanning superpowers — Trivy, Gitleaks, Semgrep, and a supply chain checker built to catch attacks like the **March 2026 axios npm compromise**.

## Install

```bash
pip install security-autopilot
# or
uvx security-autopilot
```

## Connect to Claude Code

Add to `~/.claude/claude.json`:

```json
{
  "mcpServers": {
    "security-autopilot": {
      "command": "uvx",
      "args": ["security-autopilot"]
    }
  }
}
```

## Usage

Once connected, just talk to Claude Code naturally:

- "scan this project"
- "any secrets exposed in this repo?"
- "is my supply chain safe?"
- "watch this project for new vulnerabilities"

## What it catches (that npm audit misses)

- Maintainer account hijacks (axios March 2026 pattern)
- Missing SLSA provenance on new package versions
- `postinstall` script injection
- Floating version pins that allow silent upgrades
- Known-bad version blocklist (updated by community)

## Scanners

| Scanner | Catches | Requires |
|---|---|---|
| Supply Chain | Known-bad versions, hijacks, lifecycle scripts | nothing |
| Trivy | CVEs in deps + containers | `brew install trivy` |
| Gitleaks | Exposed secrets + credentials | `brew install gitleaks` |
| Semgrep | SAST code-level bugs | `pip install semgrep` |

## License

MIT
