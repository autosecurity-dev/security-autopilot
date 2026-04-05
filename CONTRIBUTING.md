# Contributing to Security Autopilot

Thanks for helping keep the community safer. There are three ways to contribute:

1. **Report a newly discovered malicious package** — add it to the blocklist
2. **Add a new scanner** — wrap a new CLI security tool
3. **Fix a bug** — open an issue or send a PR

---

## Quick start

```bash
git clone git@github.com:autosecurity-dev/security-autopilot.git
cd security-autopilot
uv sync --dev
uv run pytest tests/ -v
```

All tests must pass before opening a PR.

---

## Adding a malicious package to KNOWN_BAD

Open `mcp_server/tools/supply_chain.py` and add an entry to the `KNOWN_BAD` list:

```python
{"name": "package-name", "version": "x.y.z", "reason": "brief description — link to advisory"},
```

Rules:
- **Exact version only** — never a range. We flag a specific known-bad release, not a package.
- **Reason must include a source** — link to an advisory, blog post, or CVE. No unsourced entries.
- **One entry per bad version** — if multiple versions are affected, add one line each.

Then add a test fixture and a test case in `tests/test_supply_chain.py` that asserts the package is flagged as `critical`.

---

## Adding a new scanner

1. Create `mcp_server/tools/my_scanner.py`
2. Implement `async def scan(project_path: str) -> list[dict]`
3. Every finding must conform to `schemas/finding.json` (id, scanner, severity, title, description, remediation)
4. If the CLI tool is not installed, return one `info` finding — never raise an exception
5. Add `my_scanner` to `_SCANNER_MAP` in `mcp_server/tools/scan_repo.py`
6. Register the scanner name in `schemas/finding.json` → `scanner.enum`
7. Add tests: at minimum a happy-path test and a "tool not installed" test

See `mcp_server/tools/trivy.py` or `gitleaks.py` for reference implementations.

---

## Fixing a bug

1. Open an issue describing the bug (use the Bug Report template)
2. Fork the repo and create a branch: `fix/short-description`
3. Write a failing test that reproduces the bug, then fix it
4. Open a PR — CI must pass

---

## Conventions

**Branch naming:** `feat/`, `fix/`, `chore/`, `refactor/`

**Commit messages:**
```
feat: short description of what was added
fix: short description of what was fixed
chore: dependency bump, config change, etc.
```

**Code style:** follow the patterns already in the file you're editing. All scanner functions are `async def`. No blocking I/O on the event loop.

---

## PR checklist

- [ ] `uv run pytest tests/ -v` passes locally
- [ ] If adding to KNOWN_BAD: advisory/source linked in the `reason` field
- [ ] If adding a scanner: all 7 steps above completed
- [ ] No secrets, tokens, or `.env` files committed

---

## Reporting a vulnerability

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md).
