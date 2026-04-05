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

        # Start ongoing scheduler + watchers for already-found projects
        projects = _find_existing_projects()
        watcher_tasks = [
            asyncio.create_task(start_watcher(str(p)))
            for p in projects
            if str(p) not in _active
        ]

        scheduler_task = asyncio.create_task(run_scheduler())

        await stop_event.wait()

        # Cancel everything cleanly
        for task in [scheduler_task, *watcher_tasks]:
            task.cancel()
        await asyncio.gather(scheduler_task, *watcher_tasks, return_exceptions=True)

    finally:
        _remove_pid()
        log.info("Security Autopilot daemon stopped")


def main() -> None:
    """Entry point for `security-autopilot-daemon` CLI."""
    _setup_logging()
    asyncio.run(_run())


if __name__ == "__main__":
    main()
