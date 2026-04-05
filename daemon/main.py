"""Security Autopilot background daemon.

Standalone entry point that:
1. Scans all existing projects on first run
2. Watches for new projects and manifest changes forever
3. Sends desktop notifications on critical/high findings

Start manually:   python -m daemon.main
As installed CLI: security-autopilot-daemon
Via launchd/systemd: handled by install.sh
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime
from pathlib import Path

from .scheduler import WATCHED_ROOTS, PROJECT_MARKERS, run_scheduler, _active
from .watcher import start_watcher, _notify, _run_scan
from mcp_server.aggregator import store
from mcp_server.updater import get_latest_version, get_current_version, is_newer, self_update, restart_daemon

# ── Paths ─────────────────────────────────────────────────────────────────────
DATA_DIR = Path.home() / ".security-autopilot"
PID_FILE = DATA_DIR / "daemon.pid"
LOG_FILE = DATA_DIR / "daemon.log"
INITIAL_SCAN_FLAG = DATA_DIR / "initial_scan_done"

# Max concurrent project scans during initial sweep
_SCAN_CONCURRENCY = 4


# ── Logging ───────────────────────────────────────────────────────────────────
def _setup_logging() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fmt = "[%(asctime)s] %(levelname)s %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    handlers: list[logging.Handler] = [
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ]
    logging.basicConfig(level=logging.INFO, format=fmt, datefmt=datefmt, handlers=handlers)


log = logging.getLogger(__name__)


# ── PID management ────────────────────────────────────────────────────────────
def _write_pid() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))


def _remove_pid() -> None:
    PID_FILE.unlink(missing_ok=True)


# ── Initial project discovery ─────────────────────────────────────────────────
def _find_existing_projects() -> list[Path]:
    """Walk watched roots up to 2 levels deep, return dirs with manifest files."""
    found: list[Path] = []
    for root in WATCHED_ROOTS:
        if not root.exists():
            continue
        # Level 1: root itself
        if any((root / m).exists() for m in PROJECT_MARKERS):
            found.append(root)
        # Level 2: immediate subdirectories
        try:
            for entry in root.iterdir():
                if not entry.is_dir():
                    continue
                if any((entry / m).exists() for m in PROJECT_MARKERS):
                    found.append(entry)
        except PermissionError:
            continue
    return found


async def _initial_scan() -> None:
    """Scan all existing projects once, send a summary notification."""
    if INITIAL_SCAN_FLAG.exists():
        log.info("Initial scan already done — skipping")
        return

    projects = _find_existing_projects()
    if not projects:
        log.info("No existing projects found in watched directories")
        INITIAL_SCAN_FLAG.touch()
        return

    log.info("Initial scan: found %d project(s) — scanning now", len(projects))
    _notify("Security Autopilot", f"Scanning {len(projects)} existing project(s)…")

    total_critical = 0
    total_high = 0
    semaphore = asyncio.Semaphore(_SCAN_CONCURRENCY)

    async def scan_one(path: Path) -> None:
        nonlocal total_critical, total_high
        async with semaphore:
            try:
                log.info("Scanning %s", path)
                from mcp_server.tools.scan_repo import scan_repo
                result = await scan_repo(str(path), checks=["all"])
                await store(result["findings"], str(path))
                total_critical += result["summary"]["critical"]
                total_high += result["summary"]["high"]
                log.info(
                    "  %s — %d critical, %d high",
                    path.name,
                    result["summary"]["critical"],
                    result["summary"]["high"],
                )
            except Exception as exc:
                log.error("Failed to scan %s: %s", path, exc)

    await asyncio.gather(*(scan_one(p) for p in projects))

    INITIAL_SCAN_FLAG.touch()

    if total_critical + total_high == 0:
        msg = f"Scanned {len(projects)} project(s) — all clear"
        log.info(msg)
        _notify("Security Autopilot", msg)
    else:
        msg = (
            f"Scanned {len(projects)} project(s) — "
            f"{total_critical} critical, {total_high} high issue(s) found. "
            "Ask Claude: 'show my security findings'"
        )
        log.warning(msg)
        _notify("Security Autopilot — Action Required", msg)


# ── Live threat feed refresh ──────────────────────────────────────────────────
async def _refresh_threat_feeds() -> None:
    """Walk watched projects, collect packages, and refresh the threat feed cache."""
    try:
        from mcp_server.tools.threat_feeds import fetch_all_feeds
        from mcp_server.tools.threat_cache import save_threats
        import json

        npm_packages: list[dict] = []
        pip_packages: list[dict] = []

        for project_dir in _find_existing_projects():
            pkg_json = project_dir / "package.json"
            if pkg_json.exists():
                try:
                    data = json.loads(pkg_json.read_text())
                    deps = {
                        **data.get("dependencies", {}),
                        **data.get("devDependencies", {}),
                    }
                    for name, ver_spec in deps.items():
                        version = ver_spec.lstrip("^~=>< ")
                        if version:
                            npm_packages.append({"name": name, "version": version})
                except Exception:
                    pass

            req_txt = project_dir / "requirements.txt"
            if req_txt.exists():
                try:
                    for line in req_txt.read_text().splitlines():
                        line = line.strip()
                        if not line or line.startswith("#") or "==" not in line:
                            continue
                        name, version = line.split("==", 1)
                        pip_packages.append({"name": name.strip(), "version": version.strip()})
                except Exception:
                    pass

        if not npm_packages and not pip_packages:
            log.debug("Threat feed refresh: no packages found in watched projects")
            return

        threats = await fetch_all_feeds(npm_packages, pip_packages)
        if threats:
            await save_threats(threats)
            log.info("Threat feeds updated — %d entries cached", len(threats))
        else:
            log.info("Threat feeds refreshed — no new threats found")

    except Exception as exc:
        log.warning("Threat feed refresh failed: %s", exc)


async def _periodic_threat_refresh() -> None:
    """Refresh threat feeds every 24 hours."""
    while True:
        await asyncio.sleep(24 * 60 * 60)
        try:
            await _refresh_threat_feeds()
        except Exception as exc:
            log.warning("Periodic threat refresh failed: %s", exc)


# ── Auto-update ───────────────────────────────────────────────────────────────
async def _check_for_update() -> None:
    """Check PyPI for a newer version and self-update if available."""
    current = get_current_version()
    latest = get_latest_version()

    if latest is None:
        log.debug("Update check skipped — could not reach PyPI")
        return

    if not is_newer(latest, current):
        log.info("Already on latest version (%s)", current)
        return

    log.info("Update available: %s → %s", current, latest)
    success = await self_update(current, latest)

    if success:
        _notify(
            "Security Autopilot updated",
            f"v{current} → v{latest} — restarting now",
        )
        restart_daemon()  # os.execv — replaces this process cleanly
    else:
        log.warning("Auto-update failed — run install.sh to update manually")
        _notify(
            "Security Autopilot — Update available",
            f"v{latest} available. Run install.sh to update (auto-update failed).",
        )


async def _periodic_update_check() -> None:
    """Check for updates every 24 hours after the first startup check."""
    while True:
        await asyncio.sleep(24 * 60 * 60)
        try:
            await _check_for_update()
        except Exception as exc:
            log.warning("Periodic update check failed: %s", exc)


# ── Main ──────────────────────────────────────────────────────────────────────
async def _run() -> None:
    _write_pid()
    log.info("Security Autopilot daemon started (pid %d)", os.getpid())

    # Graceful shutdown on SIGTERM / SIGINT
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _handle_signal() -> None:
        log.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _handle_signal)

    try:
        await _initial_scan()
        await _check_for_update()  # Check for update on every startup
        await _refresh_threat_feeds()  # Refresh live threat intel on startup

        # Start ongoing scheduler + watchers for already-found projects
        projects = _find_existing_projects()
        watcher_tasks = [
            asyncio.create_task(start_watcher(str(p)))
            for p in projects
            if str(p) not in _active
        ]

        scheduler_task = asyncio.create_task(run_scheduler())
        update_task = asyncio.create_task(_periodic_update_check())
        threat_task = asyncio.create_task(_periodic_threat_refresh())

        await stop_event.wait()

        # Cancel everything cleanly
        for task in [scheduler_task, update_task, threat_task, *watcher_tasks]:
            task.cancel()
        await asyncio.gather(scheduler_task, update_task, threat_task, *watcher_tasks, return_exceptions=True)

    finally:
        _remove_pid()
        log.info("Security Autopilot daemon stopped")


def main() -> None:
    """Entry point for `security-autopilot-daemon` CLI."""
    _setup_logging()
    asyncio.run(_run())


if __name__ == "__main__":
    main()
