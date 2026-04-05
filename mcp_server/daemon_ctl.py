"""Daemon lifecycle control for the `security-autopilot daemon` subcommand.

Handles start, stop, and status for the background daemon on macOS (launchd)
and Linux (systemd --user).  Called from mcp_server/server.py:main() when
the first CLI argument is "daemon".
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Paths (mirrors daemon/main.py — no import to avoid circular deps) ──────────
DATA_DIR    = Path.home() / ".security-autopilot"
PID_FILE    = DATA_DIR / "daemon.pid"
LOG_FILE    = DATA_DIR / "daemon.log"

# macOS launchd
PLIST_LABEL = "dev.securityautopilot.daemon"
PLIST_PATH  = Path.home() / "Library" / "LaunchAgents" / f"{PLIST_LABEL}.plist"

# Linux systemd
SYSTEMD_SVC  = "security-autopilot"
SYSTEMD_FILE = Path.home() / ".config" / "systemd" / "user" / f"{SYSTEMD_SVC}.service"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _current_version() -> str:
    try:
        from importlib.metadata import version
        return version("security-autopilot")
    except Exception:
        return "unknown"


def _read_pid() -> int | None:
    """Return PID from PID file, or None if missing/invalid."""
    try:
        return int(PID_FILE.read_text().strip())
    except Exception:
        return None


def _is_running(pid: int) -> bool:
    """Return True if the process with this PID is alive."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _uptime_str(pid_file: Path) -> str:
    """Approximate uptime from PID file mtime."""
    try:
        mtime = pid_file.stat().st_mtime
        elapsed = datetime.now(timezone.utc).timestamp() - mtime
        hours, rem = divmod(int(elapsed), 3600)
        minutes = rem // 60
        if hours:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    except Exception:
        return "unknown"


def _run(cmd: list[str]) -> tuple[int, str]:
    """Run a shell command, return (returncode, combined output)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.returncode, (result.stdout + result.stderr).strip()
    except FileNotFoundError:
        return 1, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 1, "Command timed out"


def _not_installed_message() -> str:
    return (
        "Daemon is not installed. Run the installer first:\n"
        "  curl -fsSL https://raw.githubusercontent.com/autosecurity-dev/"
        "security-autopilot/main/install.sh | sh"
    )


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_start() -> None:
    """Start the daemon via launchd (macOS) or systemd (Linux)."""
    pid = _read_pid()
    if pid and _is_running(pid):
        print(f"Daemon is already running (pid {pid})")
        return

    if sys.platform == "darwin":
        if not PLIST_PATH.exists():
            print(_not_installed_message())
            sys.exit(1)
        rc, out = _run(["launchctl", "load", str(PLIST_PATH)])
        if rc == 0:
            print("Daemon started.")
        else:
            print(f"Failed to start daemon: {out}")
            sys.exit(1)

    elif sys.platform.startswith("linux"):
        if not SYSTEMD_FILE.exists():
            print(_not_installed_message())
            sys.exit(1)
        _run(["systemctl", "--user", "daemon-reload"])
        rc, out = _run(["systemctl", "--user", "start", SYSTEMD_SVC])
        if rc == 0:
            print("Daemon started.")
        else:
            print(f"Failed to start daemon: {out}")
            sys.exit(1)

    else:
        print(f"Unsupported platform: {sys.platform}")
        sys.exit(1)


def cmd_stop() -> None:
    """Stop the daemon via launchd (macOS) or systemd (Linux)."""
    if sys.platform == "darwin":
        if not PLIST_PATH.exists():
            print(_not_installed_message())
            sys.exit(1)
        rc, out = _run(["launchctl", "unload", str(PLIST_PATH)])
        if rc == 0:
            print("Daemon stopped.")
        else:
            print(f"Failed to stop daemon: {out}")
            sys.exit(1)

    elif sys.platform.startswith("linux"):
        rc, out = _run(["systemctl", "--user", "stop", SYSTEMD_SVC])
        if rc == 0:
            print("Daemon stopped.")
        else:
            print(f"Failed to stop daemon: {out}")
            sys.exit(1)

    else:
        print(f"Unsupported platform: {sys.platform}")
        sys.exit(1)

    # Clean up stale PID file if process is gone
    pid = _read_pid()
    if pid and not _is_running(pid):
        PID_FILE.unlink(missing_ok=True)


def cmd_status() -> None:
    """Show daemon status, uptime, version, and recent log lines."""
    version = _current_version()
    print(f"Security Autopilot v{version}")
    print()

    pid = _read_pid()
    if pid and _is_running(pid):
        uptime = _uptime_str(PID_FILE)
        print(f"  Status:  running")
        print(f"  PID:     {pid}")
        print(f"  Uptime:  {uptime}")
    else:
        print("  Status:  stopped")
        if pid:
            # Stale PID file
            PID_FILE.unlink(missing_ok=True)

    print()

    # Last 10 log lines
    if LOG_FILE.exists():
        try:
            lines = LOG_FILE.read_text(errors="replace").splitlines()
            tail = lines[-10:] if len(lines) > 10 else lines
            if tail:
                print(f"  Log ({LOG_FILE}):")
                for line in tail:
                    print(f"    {line}")
            else:
                print("  Log: (empty)")
        except Exception:
            print(f"  Log: (could not read {LOG_FILE})")
    else:
        print("  Log: (no log file yet)")


# ── Entry point ────────────────────────────────────────────────────────────────

def run_daemon_command(args: list[str]) -> None:
    """Dispatch daemon subcommand from sys.argv[2:]."""
    subcommand = args[0] if args else "status"
    dispatch = {
        "start":  cmd_start,
        "stop":   cmd_stop,
        "status": cmd_status,
    }
    fn = dispatch.get(subcommand)
    if fn is None:
        print(f"Unknown subcommand: '{subcommand}'")
        print("Usage: security-autopilot daemon [start|stop|status]")
        sys.exit(1)
    fn()
