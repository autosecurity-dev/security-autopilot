"""Tests for the Sapphire Sleet / axios attack pattern detector.

Each test maps to one of the 8 checks in the Microsoft Threat Intelligence
report on the March 31 2026 axios supply chain compromise.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_server.tools.axios_attack_pattern import run_axios_checks


# ── Test 1: plain-crypto-js at any version triggers CRITICAL ─────────────────

@pytest.mark.asyncio
async def test_plain_crypto_js_any_version_triggers_critical(tmp_path: Path) -> None:
    """plain-crypto-js appearing in package.json at any version → CRITICAL.

    Maps to Check 1 (KNOWN_BAD list in supply_chain.py). This test verifies the
    full scan() pipeline flags it — we call supply_chain.scan() directly since
    run_axios_checks() doesn't duplicate Check 1.
    """
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "test-app",
        "dependencies": {"plain-crypto-js": "4.2.0"},
    }))

    from mcp_server.tools.supply_chain import scan
    findings = await scan(str(tmp_path))
    critical = [f for f in findings if f["severity"] == "critical"]

    assert critical, "Expected at least one CRITICAL finding for plain-crypto-js"
    pkcjs = [f for f in critical if "plain-crypto-js" in f["title"].lower()]
    assert pkcjs, (
        f"Expected CRITICAL finding mentioning plain-crypto-js. "
        f"Critical findings: {[f['title'] for f in critical]}"
    )


# ── Test 2: C2 string in node_modules triggers CRITICAL ──────────────────────

@pytest.mark.asyncio
async def test_c2_indicator_in_node_modules_triggers_critical(tmp_path: Path) -> None:
    """A C2 string inside an installed package file → CRITICAL 'C2 indicator' finding."""
    # Simulate an installed plain-crypto-js with an embedded C2 string
    pkg_dir = tmp_path / "node_modules" / "plain-crypto-js"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "setup.js").write_text(
        "// legit-looking code\n"
        "const host = 'sfrclak.com';\n"  # C2 domain from the attack
        "fetch(host);\n"
    )

    findings = await run_axios_checks(str(tmp_path))
    critical = [f for f in findings if f["severity"] == "critical"]

    assert critical, "Expected at least one CRITICAL finding for C2 indicator"
    c2_findings = [f for f in critical if "c2 indicator" in f["title"].lower()]
    assert c2_findings, (
        f"Expected finding with 'C2 indicator' in title. "
        f"Critical titles: {[f['title'] for f in critical]}"
    )


# ── Test 3: Caret pin on axios triggers HIGH ──────────────────────────────────

@pytest.mark.asyncio
async def test_caret_pin_on_axios_triggers_high(tmp_path: Path) -> None:
    """axios pinned with ^ that resolves to malicious version → HIGH finding."""
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "test-app",
        "dependencies": {"axios": "^1.14.0"},  # would auto-upgrade to 1.14.1
    }))

    findings = await run_axios_checks(str(tmp_path))
    high = [f for f in findings if f["severity"] == "high"]

    assert high, "Expected at least one HIGH finding for caret pin"
    autoupgrade = [f for f in high if "silent upgrade" in f["title"].lower() or "auto" in f["title"].lower()]
    assert autoupgrade, (
        f"Expected HIGH finding about auto-upgrade vector. "
        f"High findings: {[f['title'] for f in high]}"
    )


# ── Test 4: Missing lockfile triggers HIGH ────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_lockfile_triggers_high(tmp_path: Path) -> None:
    """package.json present, no lockfile → HIGH finding."""
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "test-app",
        "dependencies": {"express": "^4.18.0"},
    }))
    # Deliberately do NOT create package-lock.json

    findings = await run_axios_checks(str(tmp_path))
    high = [f for f in findings if f["severity"] == "high"]

    assert high, "Expected at least one HIGH finding for missing lockfile"
    lockfile_findings = [f for f in high if "lockfile" in f["title"].lower()]
    assert lockfile_findings, (
        f"Expected HIGH finding about missing lockfile. "
        f"High findings: {[f['title'] for f in high]}"
    )


# ── Test 5: Transitive dependency detection ───────────────────────────────────

@pytest.mark.asyncio
async def test_transitive_dependency_triggers_critical(tmp_path: Path) -> None:
    """A package in lockfile that depends on axios@1.14.1 → CRITICAL finding."""
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "test-app",
        "dependencies": {"some-sdk": "2.0.0"},
        # No direct axios dependency — it's transitive
    }))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "test-app",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {"some-sdk": "2.0.0"},
            },
            "node_modules/some-sdk": {
                "version": "2.0.0",
                "dependencies": {"axios": "1.14.1"},  # transitive compromised dep
            },
            "node_modules/axios": {
                "version": "1.14.1",
            },
        },
    }))

    findings = await run_axios_checks(str(tmp_path))
    critical = [f for f in findings if f["severity"] == "critical"]

    assert critical, "Expected at least one CRITICAL finding for transitive dep"
    transitive = [f for f in critical if "transitive" in f["title"].lower()]
    assert transitive, (
        f"Expected CRITICAL finding about transitive dependency. "
        f"Critical findings: {[f['title'] for f in critical]}"
    )


# ── Test 6: Exact safe pin produces no axios-related findings ─────────────────

@pytest.mark.asyncio
async def test_exact_safe_pin_produces_no_axios_findings(tmp_path: Path) -> None:
    """axios pinned exactly to 1.14.0 with matching lockfile → no CRITICAL or HIGH for axios."""
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "test-app",
        "dependencies": {"axios": "1.14.0"},
    }))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "test-app",
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"axios": "1.14.0"}},
            "node_modules/axios": {"version": "1.14.0"},
        },
    }))

    findings = await run_axios_checks(str(tmp_path))
    axios_bad = [
        f for f in findings
        if f["severity"] in ("critical", "high")
        and "axios" in f["title"].lower()
        and "ci" not in f["title"].lower()  # exclude CI/CD findings
    ]

    assert not axios_bad, (
        f"Expected no CRITICAL/HIGH findings for a safe axios pin, "
        f"got: {[f['title'] for f in axios_bad]}"
    )


# ── Test 7: macOS artifact path check ────────────────────────────────────────

@pytest.mark.asyncio
async def test_macos_artifact_detection_triggers_critical(tmp_path: Path) -> None:
    """If the RAT artifact path exists → CRITICAL 'compromised' finding."""
    with patch("mcp_server.tools.axios_attack_pattern.sys") as mock_sys, \
         patch("mcp_server.tools.axios_attack_pattern.Path") as mock_path_cls:

        # Simulate macOS
        mock_sys.platform = "darwin"

        # Make Path("/Library/Caches/com.apple.act.mond").exists() return True
        # but leave other Path() calls working normally
        real_path = Path

        def path_side_effect(arg="", *args):
            p = real_path(arg, *args)
            if str(arg) == "/Library/Caches/com.apple.act.mond":
                class FakePath:
                    def exists(self): return True
                    def is_dir(self): return False
                    def __str__(self): return "/Library/Caches/com.apple.act.mond"
                    def __truediv__(self, other): return real_path(str(self)) / other
                return FakePath()
            return p

        mock_path_cls.side_effect = path_side_effect

        from mcp_server.tools import axios_attack_pattern
        # Directly call the artifact check
        findings = await axios_attack_pattern._check_artifacts()

    # If mocking was too complex, do a simpler direct mock on os.path.exists
    if not findings:
        with patch("pathlib.Path.exists", return_value=True), \
             patch("mcp_server.tools.axios_attack_pattern.sys") as mock_sys2:
            mock_sys2.platform = "darwin"
            findings = await axios_attack_pattern._check_artifacts()

    # At this point findings may still be empty if the mock didn't take hold.
    # Use the simplest possible approach: directly test with monkeypatching
    if not findings:
        import mcp_server.tools.axios_attack_pattern as m
        original_platform = m.sys.platform
        try:
            m.sys.platform = "darwin"
            artifact_path = Path("/Library/Caches/com.apple.act.mond")
            with patch.object(artifact_path.__class__, "exists", return_value=True):
                findings = await m._check_artifacts()
        finally:
            m.sys.platform = original_platform

    critical = [f for f in findings if f["severity"] == "critical"]
    assert critical, (
        "Expected at least one CRITICAL finding when RAT artifact path exists. "
        "If this fails, the artifact detection for macOS may not be triggering."
    )
    compromised = [f for f in critical if "compromised" in f["description"].lower()
                   or "compromised" in f["title"].lower()]
    assert compromised, (
        f"Expected 'compromised' in finding description/title. "
        f"Critical findings: {[(f['title'], f['description'][:80]) for f in critical]}"
    )
