"""Auto-detection and scheduling daemon.

Watches common dev directories and ~/.claude/ for new projects,
registers them for automatic scanning within 60 seconds of detection.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

from .watcher import start_watcher

# Manifest files that indicate a project root
PROJECT_MARKERS = {
    "package.json", "requirements.txt", "go.mod", "Cargo.toml", "Gemfile"
}

# Common dev directories to watch for new projects
WATCHED_ROOTS = [
    Path.home() / "projects",
    Path.home() / "code",
    Path.home() / "dev",
    Path.home() / "workspace",
    Path.home() / "Desktop" / "projects",
    Path.home() / ".claude",
]

# Active watcher tasks keyed by project path
_active: dict[str, asyncio.Task] = {}


class _NewProjectHandler(FileSystemEventHandler):
    """Detects new project directories and registers them for scanning."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        """Initialise with the running event loop."""
        super().__init__()
        self.loop = loop

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation events — look for new manifest files."""
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.name in PROJECT_MARKERS:
            project_dir = str(path.parent)
            asyncio.ensure_future(
                _register_project(project_dir), loop=self.loop
            )


async def _register_project(project_path: str) -> None:
    """Register a new project for scanning with a 60-second initial delay.

    Args:
        project_path: Absolute path to the new project directory.
    """
    if project_path in _active and not _active[project_path].done():
        return  # already watching

    # Wait 60 seconds to let the project finish initialising
    await asyncio.sleep(60)

    _active[project_path] = asyncio.create_task(start_watcher(project_path))


async def run_scheduler() -> None:
    """Start watching all configured root directories for new projects.

    Runs indefinitely — call from an asyncio entry point.
    """
    loop = asyncio.get_running_loop()
    handler = _NewProjectHandler(loop)
    observer = Observer()

    for root in WATCHED_ROOTS:
        if root.exists():
            observer.schedule(handler, str(root), recursive=False)

    observer.start()

    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        observer.stop()
        observer.join()
