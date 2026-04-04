"""Filesystem watcher daemon.

Monitors registered project directories and triggers re-scans when
dependency manifest files change. Also emits desktop notifications
on new HIGH or CRITICAL findings.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

from mcp_server.tools.scan_repo import scan_repo
from mcp_server.aggregator import store, get_findings

# Files that trigger a re-scan when modified
TRIGGER_FILES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
}


def _notify(title: str, message: str) -> None:
    """Send a desktop notification (macOS only; silently skipped elsewhere)."""
    if sys.platform != "darwin":
        return
    try:
        script = f'display notification "{message}" with title "{title}" sound name "Basso"'
        subprocess.run(["osascript", "-e", script], check=False, timeout=3)
    except Exception:
        pass


class _ManifestChangeHandler(FileSystemEventHandler):
    """Watchdog event handler that enqueues re-scans on manifest changes."""

    def __init__(self, project_path: str, loop: asyncio.AbstractEventLoop) -> None:
        """Initialise with the project path and the running event loop."""
        super().__init__()
        self.project_path = project_path
        self.loop = loop
        self._debounce_task: asyncio.TimerHandle | None = None

    def on_any_event(self, event: FileSystemEvent) -> None:
        """Handle any filesystem event — filter to manifest files only."""
        if event.is_directory:
            return
        filename = Path(event.src_path).name
        if filename in TRIGGER_FILES:
            # Debounce: cancel pending scan and schedule a new one in 2s
            if self._debounce_task:
                self._debounce_task.cancel()
            self._debounce_task = self.loop.call_later(
                2.0,
                lambda: asyncio.ensure_future(
                    _run_scan(self.project_path), loop=self.loop
                ),
            )


async def _run_scan(project_path: str) -> None:
    """Run a full scan on project_path and notify on new critical/high findings."""
    prev_high = {
        f["id"]
        for f in await get_findings(project_path=project_path)
        if f["severity"] in ("critical", "high")
    }

    result = await scan_repo(project_path, checks=["all"])
    await store(result["findings"], project_path)

    new_high = [
        f for f in result["findings"]
        if f["severity"] in ("critical", "high") and f["id"] not in prev_high
    ]

    if new_high:
        titles = ", ".join(f["title"] for f in new_high[:3])
        _notify(
            "Security Autopilot — New Findings",
            f"{len(new_high)} new {'critical' if any(f['severity']=='critical' for f in new_high) else 'high'} issue(s): {titles}",
        )


async def start_watcher(project_path: str) -> None:
    """Start a watchdog observer on project_path and run periodic full scans.

    Runs indefinitely — intended to be launched as an asyncio Task.

    Args:
        project_path: Absolute path to the project directory to watch.
    """
    loop = asyncio.get_running_loop()
    handler = _ManifestChangeHandler(project_path, loop)
    observer = Observer()
    observer.schedule(handler, project_path, recursive=True)
    observer.start()

    # Initial scan on startup
    await _run_scan(project_path)

    try:
        while True:
            # Full scan every 24 hours regardless of file changes
            await asyncio.sleep(24 * 60 * 60)
            await _run_scan(project_path)
    finally:
        observer.stop()
        observer.join()
