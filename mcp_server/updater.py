"""Self-update logic for the Security Autopilot daemon.

Checks PyPI once on startup and every 24 hours. If a newer version is
available, silently upgrades via `uv tool install --upgrade` and restarts
the daemon process. Uses stdlib only — no extra dependencies.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from importlib.metadata import version as pkg_version, PackageNotFoundError

log = logging.getLogger(__name__)

_PYPI_URL = "https://pypi.org/pypi/security-autopilot/json"
_PACKAGE_NAME = "security-autopilot"


def get_latest_version() -> str | None:
    """Fetch the latest published version from PyPI. Returns None on any error."""
    try:
        req = urllib.request.Request(_PYPI_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data["info"]["version"]
    except (urllib.error.URLError, OSError, KeyError, json.JSONDecodeError):
        return None


def get_current_version() -> str:
    """Return the currently installed version of security-autopilot."""
    try:
        return pkg_version(_PACKAGE_NAME)
    except PackageNotFoundError:
        return "0.0.0"


def is_newer(latest: str, current: str) -> bool:
    """Return True if latest is strictly newer than current."""
    try:
        def to_tuple(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.split("."))
        return to_tuple(latest) > to_tuple(current)
    except (ValueError, AttributeError):
        return False


async def self_update(current: str, latest: str) -> bool:
    """Run `uv tool install --upgrade security-autopilot`. Returns True on success."""
    log.info("Updating %s → %s", current, latest)
    try:
        proc = await asyncio.create_subprocess_exec(
            "uv", "tool", "install", "--upgrade", _PACKAGE_NAME,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode == 0:
            log.info("Update successful: %s → %s", current, latest)
            return True
        else:
            log.warning("Update failed: %s", stderr.decode().strip())
            return False
    except Exception as exc:
        log.warning("Update failed: %s", exc)
        return False


def restart_daemon() -> None:
    """Replace the current process with a fresh copy of itself."""
    log.info("Restarting daemon after update...")
    os.execv(sys.executable, [sys.executable] + sys.argv)
