# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private security advisory instead:
**[Report a vulnerability](https://github.com/autosecurity-dev/security-autopilot/security/advisories/new)**

This keeps the report private until a fix is released.

---

## What to include

- Steps to reproduce
- Affected version (run `security-autopilot --version` or check `pyproject.toml`)
- What an attacker could achieve
- Any suggested fix (optional but appreciated)

---

## Scope

In scope:
- Scanner logic producing false negatives that would hide a real attack
- MCP server accepting untrusted input in a way that enables code execution
- Auto-patch applying a version that is itself malicious
- Daemon writing credentials or findings to world-readable paths

Out of scope:
- Vulnerabilities in wrapped CLI tools (Trivy, Gitleaks, Semgrep) — report those upstream
- Findings about packages in your own projects (that's expected behavior)
- Social engineering

---

## Response timeline

| Severity | Acknowledgement | Patch target |
|---|---|---|
| Critical | 24 hours | 3 days |
| High | 48 hours | 7 days |
| Medium/Low | 5 days | Next release |

---

## Supported versions

Only the latest version published on PyPI receives security fixes.
