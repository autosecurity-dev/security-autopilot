"""Auto-installer for CLI scanner dependencies.

Detects the OS and available package managers, then installs
trivy, gitleaks, or semgrep automatically when they are missing.
Supports macOS (Homebrew) and Linux (apt, yum/dnf, or curl fallback).
"""
from __future__ import annotations

import asyncio
import shutil
import sys


# ---------------------------------------------------------------------------
# Install recipes per tool per platform
# ---------------------------------------------------------------------------

_BREW_NAMES = {
    "trivy":    "trivy",
    "gitleaks": "gitleaks",
    "semgrep":  "semgrep",
}

# Official install scripts / curl-based installers for Linux fallback
_LINUX_SCRIPTS = {
    "trivy": [
        # Debian/Ubuntu
        ["sh", "-c",
         "apt-get install -y wget apt-transport-https gnupg lsb-release 2>/dev/null && "
         "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - 2>/dev/null && "
         "echo 'deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main' "
         "| tee /etc/apt/sources.list.d/trivy.list && apt-get update && apt-get install -y trivy"],
        # RPM-based
        ["sh", "-c",
         "rpm -ivh https://github.com/aquasecurity/trivy/releases/latest/download/"
         "trivy_$(uname -m | sed 's/x86_64/amd64/').rpm 2>/dev/null || "
         "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"],
    ],
    "gitleaks": [
        ["sh", "-c",
         "curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/main/scripts/install.sh "
         "| sh -s -- -b /usr/local/bin"],
    ],
    "semgrep": [
        ["pip3", "install", "--quiet", "semgrep"],
    ],
}

_INSTALL_DOCS = {
    "trivy":    "https://trivy.dev/latest/getting-started/installation/",
    "gitleaks": "https://github.com/gitleaks/gitleaks#installing",
    "semgrep":  "https://semgrep.dev/docs/getting-started/",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_macos() -> bool:
    """Return True on macOS."""
    return sys.platform == "darwin"


def _is_linux() -> bool:
    """Return True on Linux."""
    return sys.platform.startswith("linux")


def _has_brew() -> bool:
    """Return True if Homebrew is available."""
    return shutil.which("brew") is not None


async def _run(cmd: list[str]) -> bool:
    """Run a shell command and return True if it exits 0."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()
        return proc.returncode == 0
    except Exception:
        return False


async def is_installed(tool: str) -> bool:
    """Return True if the tool binary is available on PATH."""
    return shutil.which(tool) is not None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def ensure_installed(tool: str) -> bool:
    """Install tool if it is not already on PATH.

    Tries Homebrew on macOS, then official Linux scripts.
    Returns True if the tool is available after the attempt.

    Args:
        tool: One of "trivy", "gitleaks", "semgrep".
    """
    if await is_installed(tool):
        return True

    print(f"[security-autopilot] {tool} not found — installing automatically...", flush=True)

    if _is_macos() and _has_brew():
        success = await _run(["brew", "install", _BREW_NAMES[tool]])
        if success and await is_installed(tool):
            print(f"[security-autopilot] {tool} installed via Homebrew.", flush=True)
            return True

    if _is_linux():
        for cmd in _LINUX_SCRIPTS.get(tool, []):
            success = await _run(cmd)
            if success and await is_installed(tool):
                print(f"[security-autopilot] {tool} installed on Linux.", flush=True)
                return True

    # All install attempts failed
    print(
        f"[security-autopilot] Could not auto-install {tool}. "
        f"Please install manually: {_INSTALL_DOCS[tool]}",
        flush=True,
    )
    return False
