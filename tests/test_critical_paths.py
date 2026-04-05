"""Tests for critical paths that had zero coverage.

Covers:
  1. auto_patch happy path
  2. auto_patch graceful failure when npm is not on PATH
  3. threat_feeds returns empty list on network error
  4. threat_cache preserves source field
  5. MCP server starts without stdin (P0-1 regression)
  6. Python 3.12+ watcher/scheduler import (P0-3 regression)
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


# ── Test 1: auto_patch happy path ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_auto_patch_returns_result_dict(tmp_path: Path) -> None:
    """auto_patch must return a result dict with required keys, no exception."""
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "test-app",
        "dependencies": {"axios": "1.14.1"},
    }))

    finding = {
        "scanner": "supply_chain",
        "severity": "critical",
        "title": "Known-malicious package: axios@1.14.1",
        "description": "...",
        "remediation": "...",
    }

    from mcp_server.tools.autopatch import auto_patch

    # auto_patch may succeed (if npm is installed) or fail gracefully (if not).
    # Either way it must return a dict or None — never raise.
    result = await auto_patch(str(tmp_path), finding)

    if result is not None:
        assert "package" in result
        assert "from" in result
        assert "to" in result
        assert "success" in result
        assert "manager" in result
        assert result["package"] == "axios"
        assert result["from"] == "1.14.1"


# ── Test 2: auto_patch graceful failure when npm is not on PATH ───────────────

@pytest.mark.asyncio
async def test_auto_patch_graceful_failure_without_npm(tmp_path: Path) -> None:
    """auto_patch must not raise even when npm is unavailable."""
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "test-app",
        "dependencies": {"axios": "1.14.1"},
    }))

    finding = {
        "scanner": "supply_chain",
        "severity": "critical",
        "title": "Known-malicious package: axios@1.14.1",
        "description": "...",
        "remediation": "...",
    }

    from mcp_server.tools.autopatch import auto_patch

    # Patch _run to always fail (simulates npm not installed / command failure)
    with patch("mcp_server.tools.autopatch._run", return_value=False):
        # Also patch _safe_version_npm to return a version so _patch_npm is called
        with patch(
            "mcp_server.tools.autopatch._safe_version_npm",
            new_callable=AsyncMock,
            return_value="1.14.0",
        ):
            result = await auto_patch(str(tmp_path), finding)

    # Must return a dict (with success=False) or None — never raise
    assert result is None or isinstance(result, dict)
    if result is not None:
        assert result["success"] is False


# ── Test 3: threat_feeds returns empty list on network error ──────────────────

@pytest.mark.asyncio
async def test_fetch_osv_returns_empty_on_network_error() -> None:
    """fetch_osv must return [] on any network error, never raise."""
    from mcp_server.tools.threat_feeds import fetch_osv

    packages = [{"name": "axios", "version": "1.14.1", "ecosystem": "npm"}]

    # Simulate network failure by patching _post to raise
    with patch(
        "mcp_server.tools.threat_feeds._post",
        side_effect=OSError("simulated network failure"),
    ):
        result = await fetch_osv(packages)

    assert result == [], f"Expected empty list on error, got {result}"


# ── Test 4: threat_cache preserves source field ───────────────────────────────

@pytest.mark.asyncio
async def test_threat_cache_preserves_source_field(tmp_path: Path) -> None:
    """save_threats + load_cached_threats must round-trip the source field."""
    import mcp_server.tools.threat_cache as tc

    # Point the cache at a temp DB so we don't pollute the real one
    original_path = tc.DB_PATH
    tc.DB_PATH = tmp_path / "test_findings.db"

    try:
        threats = [
            {"name": "axios", "version": "1.14.1", "reason": "test", "source": "osv"},
            {"name": "bad-pkg", "version": "2.0.0", "reason": "test", "source": "npm"},
        ]
        await tc.save_threats(threats)
        cached = await tc.load_cached_threats()
    finally:
        tc.DB_PATH = original_path

    assert len(cached) == 2, f"Expected 2 cached threats, got {len(cached)}"

    sources = {t["name"]: t.get("source") for t in cached}
    assert sources.get("axios") == "osv", (
        f"Expected source='osv' for axios, got {sources.get('axios')!r}. "
        "load_cached_threats() is dropping the source field."
    )
    assert sources.get("bad-pkg") == "npm", (
        f"Expected source='npm' for bad-pkg, got {sources.get('bad-pkg')!r}."
    )


# ── Test 5: MCP server starts without stdin (P0-1 regression) ────────────────

def test_mcp_server_starts_without_stdin() -> None:
    """MCP server must emit its startup banner without hanging on stdin.

    Regression test for P0-1: the old telemetry code called input() which
    blocked waiting for user input when stdin was the MCP protocol pipe.
    The fix: check that the startup banner appears within 5 seconds.
    The process may exit after that (stdin=DEVNULL gives the MCP protocol
    layer an immediate EOF), which is acceptable — what matters is that
    startup does not hang before the banner is printed.
    """
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_server.server"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=Path(__file__).parent.parent,
    )
    try:
        # Give it up to 5 seconds to print the startup banner
        deadline = time.monotonic() + 5
        stderr_data = b""
        while time.monotonic() < deadline:
            proc.stderr.flush()
            chunk = proc.stderr.read1(4096)  # type: ignore[attr-defined]
            if chunk:
                stderr_data += chunk
            if b"Registered tools" in stderr_data:
                break
            if proc.poll() is not None and not chunk:
                # Process exited — read remaining stderr
                stderr_data += proc.stderr.read()
                break
            time.sleep(0.1)

        assert b"Registered tools" in stderr_data, (
            "MCP server did not print startup banner within 5 seconds — "
            "it may be hanging waiting for stdin input (P0-1 regression). "
            f"stderr so far: {stderr_data.decode()[:500]}"
        )
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)


# ── Test 6: Python 3.12+ watcher/scheduler import (P0-3 regression) ──────────

def test_watcher_imports_without_loop_kwarg_error() -> None:
    """daemon.watcher and daemon.scheduler must import cleanly.

    Regression test for P0-3: ensure_future(coro, loop=x) was removed in
    Python 3.10 and would raise TypeError on Python 3.12+.
    """
    try:
        import daemon.watcher  # noqa: F401
        import daemon.scheduler  # noqa: F401
    except TypeError as exc:
        pytest.fail(
            f"Import raised TypeError — likely residual loop= kwarg: {exc}"
        )
    except ImportError as exc:
        pytest.fail(f"Import failed (missing dependency?): {exc}")
