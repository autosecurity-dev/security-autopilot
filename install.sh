#!/bin/sh
# install.sh — hosted at get.securityautopilot.dev
# curl -fsSL https://get.securityautopilot.dev | sh
set -e

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RESET='\033[0m'

warn() { printf "${YELLOW}[warn]${RESET} %s\n" "$1" >&2; }
info() { printf "  %s\n" "$1"; }

echo ""
echo "Installing Security Autopilot..."
echo ""

# ── 1. Detect OS ──────────────────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Darwin) IS_MAC=1 ;;
  Linux)  IS_MAC=0 ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

# ── 2. Install uv ────────────────────────────────────────────────────────────
if ! command -v uv >/dev/null 2>&1; then
  info "Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # Reload PATH so uv is available in this shell
  ENV_FILE="$HOME/.local/bin/env"
  [ -f "$ENV_FILE" ] && . "$ENV_FILE"
fi
info "uv $(uv --version)"

# ── 3. Install the MCP server ────────────────────────────────────────────────
info "Installing security-autopilot..."
uv tool install security-autopilot --quiet

# ── 4. Install external scanners (warn only on failure) ──────────────────────
try_install() {
  NAME="$1"; shift
  set +e
  "$@" >/dev/null 2>&1
  STATUS=$?
  set -e
  if [ $STATUS -eq 0 ]; then
    info "$NAME installed"
  else
    warn "$NAME failed to install — security-autopilot works without it (reduced coverage)"
  fi
}

info "Installing scanners..."

if [ "$IS_MAC" = "1" ]; then
  try_install "trivy"    brew install trivy
  try_install "gitleaks" brew install gitleaks
else
  try_install "trivy"    sh -c \
    "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
  try_install "gitleaks" sh -c \
    "LATEST=\$(curl -sfL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '\"tag_name\"' | cut -d'\"' -f4); \
     VER=\${LATEST#v}; \
     curl -sfLo /tmp/gitleaks.tar.gz \
       https://github.com/gitleaks/gitleaks/releases/download/\${LATEST}/gitleaks_\${VER}_linux_x64.tar.gz && \
     tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
     rm /tmp/gitleaks.tar.gz"
fi

# semgrep via uv — works on both platforms
try_install "semgrep" uv tool install semgrep --quiet

# ── 5. Register MCP server in ~/.claude/claude.json ──────────────────────────
info "Registering MCP server with Claude Code..."
python3 - <<'PYEOF'
import json, pathlib, sys

config_path = pathlib.Path.home() / ".claude" / "claude.json"
config_path.parent.mkdir(parents=True, exist_ok=True)

config = json.loads(config_path.read_text()) if config_path.exists() else {}
config.setdefault("mcpServers", {})

if "security-autopilot" in config["mcpServers"]:
    print("  MCP entry already present — skipping")
    sys.exit(0)

config["mcpServers"]["security-autopilot"] = {
    "command": "uvx",
    "args": ["security-autopilot"]
}
config_path.write_text(json.dumps(config, indent=2))
PYEOF

# ── 6. Register and start background daemon ───────────────────────────────────
info "Registering background daemon..."

UVX_PATH="$(command -v uvx 2>/dev/null || echo "$HOME/.local/bin/uvx")"
UV_BIN_DIR="$(dirname "$UVX_PATH")"

if [ "$IS_MAC" = "1" ]; then
  PLIST_DIR="$HOME/Library/LaunchAgents"
  PLIST_DEST="$PLIST_DIR/dev.securityautopilot.daemon.plist"
  mkdir -p "$PLIST_DIR"

  # Write plist using printf to avoid heredoc/variable-expansion issues in sh
  printf '<?xml version="1.0" encoding="UTF-8"?>\n' > "$PLIST_DEST"
  printf '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' >> "$PLIST_DEST"
  printf '<plist version="1.0"><dict>\n' >> "$PLIST_DEST"
  printf '  <key>Label</key><string>dev.securityautopilot.daemon</string>\n' >> "$PLIST_DEST"
  printf '  <key>ProgramArguments</key><array><string>%s</string><string>security-autopilot-daemon</string></array>\n' "$UVX_PATH" >> "$PLIST_DEST"
  printf '  <key>RunAtLoad</key><true/>\n' >> "$PLIST_DEST"
  printf '  <key>KeepAlive</key><true/>\n' >> "$PLIST_DEST"
  printf '  <key>StandardOutPath</key><string>%s/.security-autopilot/daemon.log</string>\n' "$HOME" >> "$PLIST_DEST"
  printf '  <key>StandardErrorPath</key><string>%s/.security-autopilot/daemon.log</string>\n' "$HOME" >> "$PLIST_DEST"
  printf '  <key>EnvironmentVariables</key><dict>\n' >> "$PLIST_DEST"
  printf '    <key>PATH</key><string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin:%s</string>\n' "$UV_BIN_DIR" >> "$PLIST_DEST"
  printf '    <key>HOME</key><string>%s</string>\n' "$HOME" >> "$PLIST_DEST"
  printf '  </dict>\n</dict></plist>\n' >> "$PLIST_DEST"

  # Unload existing (idempotent), then load
  launchctl unload "$PLIST_DEST" 2>/dev/null || true
  launchctl load "$PLIST_DEST"
  info "Daemon registered (starts at login)"

else
  SERVICE_DIR="$HOME/.config/systemd/user"
  mkdir -p "$SERVICE_DIR"

  cat > "$SERVICE_DIR/security-autopilot.service" <<SYSTEMD
[Unit]
Description=Security Autopilot — background security scanner
After=network.target

[Service]
Type=simple
ExecStart=$UVX_PATH security-autopilot-daemon
Restart=on-failure
RestartSec=10
Environment=HOME=$HOME
Environment=PATH=/usr/local/bin:/usr/bin:/bin:$UV_BIN_DIR
StandardOutput=append:$HOME/.security-autopilot/daemon.log
StandardError=append:$HOME/.security-autopilot/daemon.log

[Install]
WantedBy=default.target
SYSTEMD

  systemctl --user daemon-reload 2>/dev/null || true
  systemctl --user enable --now security-autopilot 2>/dev/null || \
    warn "Could not start systemd service — run: systemctl --user start security-autopilot"
  info "Daemon registered (starts at login)"
fi

# ── 7. Done ───────────────────────────────────────────────────────────────────
echo ""
printf "${GREEN}Security Autopilot is installed and running.${RESET}\n"
echo ""
echo "  Scanning your existing projects in the background."
echo "  You'll get a desktop notification when the first scan is complete."
echo ""
echo "  You can also open Claude Code and say:"
echo "  → 'scan this project'"
echo "  → 'show my security findings'"
echo ""
