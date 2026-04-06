# Security Autopilot — Demo Recording
# Requires: brew install vhs
# Record: vhs docs/demo.tape
# Output: docs/demo.gif

Output docs/demo.gif

Set Shell "zsh"
Set FontSize 14
Set Width 100
Set Height 38
Set Theme "Dracula"
Set Padding 24
Set Margin 8
Set CursorBlink false
Set TypingSpeed 40ms

# ── Scene 1: Show the project structure ───────────────────────────────────────

# (silently create the demo project first)
Hide
Type "mkdir -p /tmp/sa-demo/src /tmp/sa-demo/.github/workflows" Enter
Sleep 100ms
Type `cat > /tmp/sa-demo/package.json << 'EOF'` Enter
Type `{` Enter
Type `  "name": "my-app",` Enter
Type `  "version": "1.0.0",` Enter
Type `  "dependencies": {` Enter
Type `    "axios": "1.14.1",` Enter
Type `    "express": "^4.18.0",` Enter
Type `    "lodash": "^4.17.21"` Enter
Type `  }` Enter
Type `}` Enter
Type "EOF" Enter
Sleep 100ms
Type `cat > /tmp/sa-demo/src/index.js << 'EOF'` Enter
Type "const axios = require('axios');" Enter
Type "const express = require('express');" Enter
Type "const app = express();" Enter
Type "app.listen(3000);" Enter
Type "EOF" Enter
Sleep 100ms
Type `cat > /tmp/sa-demo/.github/workflows/ci.yml << 'EOF'` Enter
Type "name: CI" Enter
Type "on: [push]" Enter
Type "jobs:" Enter
Type "  build:" Enter
Type "    runs-on: ubuntu-latest" Enter
Type "    steps:" Enter
Type "      - uses: actions/checkout@v4" Enter
Type "      - run: npm install" Enter
Type "      - run: npm test" Enter
Type "EOF" Enter
Sleep 200ms
Show

# Show the project structure
Type "find /tmp/sa-demo -type f | sort" Enter
Sleep 1500ms

# Show the bad package.json
Type "cat /tmp/sa-demo/package.json" Enter
Sleep 2500ms

# ── Scene 2: Run the scan ─────────────────────────────────────────────────────

Type "security-autopilot scan /tmp/sa-demo" Enter
Sleep 8000ms

# ── Scene 3: Pause on the result ──────────────────────────────────────────────

Sleep 4000ms

# Cleanup
Hide
Type "rm -rf /tmp/sa-demo" Enter
Show
