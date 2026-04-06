# Security Autopilot — Demo Recording
# Requires: brew install vhs
# Record: vhs docs/demo.tape
# Output: docs/demo.gif

Output docs/demo.gif

Set Shell "zsh"
Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"
Set Padding 24
Set Margin 8
Set CursorBlink false
Set TypingSpeed 50ms

# ── Silently create the demo project ─────────────────────────────────────────
Hide
Type "sh docs/demo_setup.sh" Enter
Sleep 2000ms
Show

# ── Scene 1: Show the bad dependency ─────────────────────────────────────────
Type "cat /tmp/sa-demo/package.json" Enter
Sleep 2500ms

# ── Scene 2: Show the exposed secret in source code ──────────────────────────
Type "cat /tmp/sa-demo/src/api.js" Enter
Sleep 3000ms

# ── Scene 3: Run the scan ────────────────────────────────────────────────────
Type "security-autopilot scan /tmp/sa-demo" Enter
Sleep 50000ms

# ── Scene 4: Hold on results so viewers can read ─────────────────────────────
Sleep 8000ms

# ── Cleanup ───────────────────────────────────────────────────────────────────
Hide
Type "rm -rf /tmp/sa-demo" Enter
Show
