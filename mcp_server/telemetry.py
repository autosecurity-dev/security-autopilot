"""Anonymous usage telemetry for Security Autopilot.

Sends a single fire-and-forget `tool_started` event to PostHog on each
server startup, if the user has previously opted in.

Consent is written on first run automatically (opted_out). Users can opt in
by changing ~/.security-autopilot/telemetry_consent to "opted_in".

IMPORTANT: This module never reads from stdin and never blocks. The MCP
server uses stdio for the JSON-RPC protocol; any stdin read would corrupt
the protocol stream.
"""
from __future__ import annotations

import hashlib
import json
import platform
import socket
import urllib.error
import urllib.request
from pathlib import Path

# Replace with your PostHog project API key once you have one.
_POSTHOG_KEY = "YOUR_POSTHOG_KEY"
_POSTHOG_URL = "https://app.posthog.com/capture/"

_DATA_DIR = Path.home() / ".security-autopilot"
_CONSENT_FILE = _DATA_DIR / "telemetry_consent"


def _machine_id() -> str:
    """SHA256 of hostname — stable, anonymous per machine."""
    return hashlib.sha256(socket.gethostname().encode()).hexdigest()[:32]


def _send_ping(event: str) -> None:
    """Fire-and-forget POST to PostHog. Silently ignored on any error."""
    if _POSTHOG_KEY == "YOUR_POSTHOG_KEY":
        return  # key not configured yet
    payload = json.dumps({
        "api_key": _POSTHOG_KEY,
        "event": event,
        "distinct_id": _machine_id(),
        "properties": {
            "os": platform.system(),
            "python_version": platform.python_version(),
        },
    }).encode()
    req = urllib.request.Request(
        _POSTHOG_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=3)
    except (urllib.error.URLError, OSError):
        pass  # never crash the server over telemetry


def check_and_ping() -> None:
    """Ensure consent file exists, then send ping if opted in.

    On first run, silently writes opted_out — no stdin interaction, ever.
    Call once on server startup.
    """
    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not _CONSENT_FILE.exists():
        # Default to opted_out. Users can change this to "opted_in" manually.
        _CONSENT_FILE.write_text("opted_out")

    consent = _CONSENT_FILE.read_text().strip()
    if consent == "opted_in":
        _send_ping("tool_started")
