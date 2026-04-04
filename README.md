# Security Autopilot

An open-source MCP server that gives Claude Code native security scanning superpowers.

Built to catch supply chain attacks like the March 2026 axios npm compromise.

## Connect to Claude Code

Add to ~/.claude/claude.json:

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

## Tools: scan_repo, scan_file, get_findings, watch_project

## License: MIT
