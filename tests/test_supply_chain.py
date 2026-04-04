"""Tests for the supply chain scanner — axios attack fixture."""
from __future__ import annotations

import pytest
from pathlib import Path

from mcp_server.tools.supply_chain import scan

FIXTURE_PATH = str(Path(__file__).parent / "fixtures" / "axios_attack")


@pytest.mark.asyncio
async def test_detects_known_bad_axios_version() -> None:
    """Supply chain scanner must flag axios@1.14.1 as CRITICAL."""
    findings = await scan(FIXTURE_PATH)
    critical = [f for f in findings if f["severity"] == "critical"]

    assert critical, "Expected at least one CRITICAL finding for axios@1.14.1"

    axios_finding = next(
        (f for f in critical if "axios" in f["title"].lower() and "1.14.1" in f["title"]),
        None,
    )
    assert axios_finding is not None, (
        "Expected a CRITICAL finding specifically for axios@1.14.1. "
        f"Got critical findings: {[f['title'] for f in critical]}"
    )
    assert "1.14.1" in axios_finding["title"] or "1.14.1" in axios_finding["description"]
    assert "remediation" in axios_finding
    assert axios_finding["remediation"], "Remediation must not be empty"
    assert "1.14.0" in axios_finding["remediation"], (
        "Remediation should suggest downgrading to axios@1.14.0"
    )


@pytest.mark.asyncio
async def test_detects_postinstall_script() -> None:
    """Supply chain scanner must flag the postinstall lifecycle script as HIGH."""
    findings = await scan(FIXTURE_PATH)
    lifecycle_findings = [
        f for f in findings
        if "postinstall" in f["title"].lower() or "lifecycle" in f["title"].lower()
    ]

    assert lifecycle_findings, (
        "Expected a HIGH finding for the postinstall script. "
        f"All findings: {[f['title'] for f in findings]}"
    )

    finding = lifecycle_findings[0]
    assert finding["severity"] in ("high", "critical"), (
        f"postinstall script finding should be high or critical, got {finding['severity']}"
    )


@pytest.mark.asyncio
async def test_finding_schema_compliance() -> None:
    """All findings must conform to the required schema fields."""
    findings = await scan(FIXTURE_PATH)
    required_fields = {"id", "scanner", "severity", "title", "description", "remediation"}

    for finding in findings:
        missing = required_fields - set(finding.keys())
        assert not missing, f"Finding missing required fields: {missing}\nFinding: {finding}"
        assert finding["scanner"] == "supply_chain"
        assert finding["severity"] in ("critical", "high", "medium", "low", "info")
        assert finding["id"], "Finding ID must not be empty"


@pytest.mark.asyncio
async def test_floating_pins_flagged() -> None:
    """Floating version pins (^ or ~) should be flagged as LOW findings."""
    findings = await scan(FIXTURE_PATH)
    low_findings = [f for f in findings if f["severity"] == "low"]

    assert low_findings, (
        "Expected LOW findings for floating pins (^express, ^dotenv, ^jest). "
        f"All findings: {[(f['severity'], f['title']) for f in findings]}"
    )
