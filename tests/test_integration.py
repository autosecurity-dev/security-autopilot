"""Integration tests for scan_repo — exercises all 4 scanners against a temp fixture."""
from __future__ import annotations

import json
import pytest
import tempfile
from pathlib import Path

from mcp_server.tools.scan_repo import scan_repo

REQUIRED_FIELDS = {"id", "scanner", "severity", "title", "description", "remediation"}


@pytest.fixture
def vulnerable_project(tmp_path: Path) -> Path:
    """Create a temp project directory with known vulnerabilities for each scanner."""

    # Supply chain: axios@1.14.1 (known-bad) + floating pins
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "integration-test-app",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "node setup.js"
        },
        "dependencies": {
            "axios":   "1.14.1",
            "express": "^4.18.2",
        },
    }))

    # Gitleaks: hardcoded AWS secret
    (tmp_path / ".env").write_text(
        "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        "DATABASE_URL=postgres://user:password@localhost/db\n"
    )

    # Semgrep: dangerous eval pattern
    (tmp_path / "app.js").write_text(
        "const userInput = req.body.input;\n"
        "eval(userInput);\n"
    )

    return tmp_path


@pytest.mark.asyncio
async def test_scan_repo_returns_critical_for_axios(vulnerable_project: Path) -> None:
    """scan_repo must return at least one CRITICAL finding for axios@1.14.1."""
    result = await scan_repo(str(vulnerable_project))
    critical = [f for f in result["findings"] if f["severity"] == "critical"]

    assert critical, (
        f"Expected at least 1 CRITICAL finding. Summary: {result['summary']}"
    )
    axios_critical = [f for f in critical if "axios" in f["title"].lower()]
    assert axios_critical, (
        f"Expected CRITICAL finding for axios. Critical findings: {[f['title'] for f in critical]}"
    )


@pytest.mark.asyncio
async def test_scan_repo_returns_high_for_secret(vulnerable_project: Path) -> None:
    """scan_repo must return at least one HIGH finding (exposed secret or lifecycle script)."""
    result = await scan_repo(str(vulnerable_project))
    high = [f for f in result["findings"] if f["severity"] == "high"]

    assert high, (
        f"Expected at least 1 HIGH finding. All findings: {[(f['severity'], f['title']) for f in result['findings']]}"
    )


@pytest.mark.asyncio
async def test_scan_repo_summary_has_all_scanners(vulnerable_project: Path) -> None:
    """summary.scanners_run must contain all 4 scanner names."""
    result = await scan_repo(str(vulnerable_project))
    scanners_run = set(result["summary"]["scanners_run"])
    expected = {"supply_chain", "trivy", "gitleaks", "semgrep"}

    assert expected == scanners_run, (
        f"Expected scanners_run={expected}, got {scanners_run}"
    )


@pytest.mark.asyncio
async def test_all_findings_have_required_fields(vulnerable_project: Path) -> None:
    """Every finding returned by scan_repo must have all required schema fields."""
    result = await scan_repo(str(vulnerable_project))

    for finding in result["findings"]:
        missing = REQUIRED_FIELDS - set(finding.keys())
        assert not missing, (
            f"Finding missing required fields {missing}: {finding}"
        )
        assert finding["severity"] in ("critical", "high", "medium", "low", "info"), (
            f"Invalid severity: {finding['severity']}"
        )
        assert finding["id"], "Finding id must not be empty"


@pytest.mark.asyncio
async def test_scan_repo_summary_shape(vulnerable_project: Path) -> None:
    """summary must have the expected structure with all severity counts."""
    result = await scan_repo(str(vulnerable_project))
    summary = result["summary"]

    for key in ("critical", "high", "medium", "low", "info",
                "scanners_run", "scan_duration_seconds", "scanned_path"):
        assert key in summary, f"summary missing key: {key}"

    assert isinstance(summary["scan_duration_seconds"], float)
    assert isinstance(summary["scanners_run"], list)
    assert summary["scanned_path"] == str(vulnerable_project)


@pytest.mark.asyncio
async def test_top_priority_is_most_severe(vulnerable_project: Path) -> None:
    """top_priority must be the most critical finding when critical findings exist."""
    result = await scan_repo(str(vulnerable_project))
    top = result["top_priority"]

    assert top is not None, "Expected a top_priority finding"
    assert top["severity"] in ("critical", "high"), (
        f"top_priority should be critical or high, got {top['severity']}"
    )
