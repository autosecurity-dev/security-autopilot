# Demo Vulnerable App

**This project is intentionally broken. Nothing here is real.**

It exists to demonstrate Security Autopilot catching real-world attack patterns.
No code is ever executed. All "secrets" are documented fake/example values.

## What the scanners should find

### 🔴 CRITICAL — Supply Chain
- `axios@1.14.1` — known-malicious version (March 2026 RAT, postinstall dropper)
- `plain-crypto-js@4.2.1` — axios attack dropper

### 🟠 HIGH — Supply Chain
- `postinstall` script in package.json — lifecycle script injection

### 🟠 HIGH — Gitleaks (secrets in .env)
- AWS access key + secret
- GitHub personal access token
- Stripe live secret key
- Hardcoded DB password and JWT secret

### 🟠 HIGH — Semgrep (code flaws)
- `eval(req.body.code)` — remote code execution (server.js)
- `exec('ping -c 1 ' + req.body.host)` — OS command injection (server.js)
- `subprocess.call(user_input, shell=True)` — shell injection (config.py)

### 🟡 MEDIUM — Semgrep
- SQL injection via string concatenation (server.js + config.py)
- Reflected XSS — unsanitised query param in HTML response (server.js)
- MD5 used for password hashing (config.py)

### 🔵 LOW — Supply Chain
- Floating version pins (`^`) on express, lodash, mongoose, jsonwebtoken

### ⚪ INFO — Trivy
- django==2.2.0, pillow==8.2.0, requests==2.18.0, flask==0.12.0 — all have known CVEs

## How to scan it

In Claude Code:
```
scan this project: /path/to/demo/vulnerable-app
```

Or directly:
```bash
python -m mcp_server.server
# then call scan_repo with the path above
```
