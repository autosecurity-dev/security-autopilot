"""Opt-in anonymous usage telemetry for Security Autopilot.

On first run the user is prompted. If they opt in, a single anonymous
`tool_started` event is sent to PostHog on each server startup.

No SDK dependency — uses stdlib urllib only.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
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
    """Check consent and send ping if opted in. Call once on server startup."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not _CONSENT_FILE.exists():
        _prompt_consent()

    consent = _CONSENT_FILE.read_text().strip()
    if consent == "opted_in":
        _send_ping("tool_started")


def _prompt_consent() -> None:
    """Print opt-in prompt and write the user's choice to disk."""
    msg = (
        "\n┌─ Security Autopilot ─────────────────────────────────────────┐\n"
        "│  Help improve this tool by sharing anonymous usage data?      │\n"
        "│                                                                │\n"
        "│  This sends one event per startup: OS name, Python version.   │\n"
        "│  No code, no paths, no personal data. You can opt out anytime │\n"
        "│  by deleting ~/.security-autopilot/telemetry_consent          │\n"
        "│                                                                │\n"
        "│  Send anonymous usage data? [y/N]: "
    )
    print(msg, end="", file=sys.stderr, flush=True)

    try:
        answer = input().strip().lower()
    except (EOFError, OSError):
        answer = "n"

    choice = "opted_in" if answer == "y" else "opted_out"
    _CONSENT_FILE.write_text(choice)

    if choice == "opted_in":
        print("  Thanks! Sending one anonymous ping now.\n└─────────────────────────────────────────────────────────────────┘\n",
              file=sys.stderr)
        _send_ping("tool_installed")
    else:
        print("  Got it — no data will be sent.\n└──────────────────────────────────────────────────────────────────┘\n",
              file=sys.stderr)
