"""Step-by-step remediation instructions for exposed secrets.

Maps gitleaks RuleIDs to human-readable rotation steps.
RuleID is embedded in finding titles as: "Exposed {rule} secret in {file}"
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_ALERTS_LOG = Path.home() / ".security-autopilot" / "secret-alerts.log"

# Maps gitleaks RuleID patterns → rotation steps
_REMEDIATION: dict[str, list[str]] = {
    "aws": [
        "1. Go to AWS Console → IAM → Users → your user → Security credentials",
        "2. Click 'Make inactive' on the exposed key immediately",
        "3. Click 'Delete' to permanently remove it",
        "4. Click 'Create access key' to generate a new one",
        "5. Update your .env, ~/.aws/credentials, and any CI/CD secrets",
        "6. Go to CloudTrail → Event history → filter last 24h for suspicious activity",
        "7. Add .env to .gitignore to prevent future leaks",
    ],
    "github": [
        "1. Go to github.com → Settings → Developer settings → Personal access tokens",
        "2. Find the exposed token and click 'Delete'",
        "3. Generate a new token with only the scopes you need",
        "4. Update your .env and any services using the old token",
        "5. Check github.com/settings/security-log for recent activity",
        "6. Add .env to .gitignore",
    ],
    "stripe": [
        "1. Go to dashboard.stripe.com → Developers → API keys",
        "2. Click 'Roll key' on the exposed key — this invalidates it immediately",
        "3. Update your .env and any webhook configs with the new key",
        "4. Check dashboard.stripe.com → Developers → Events for suspicious charges",
        "5. If live key was exposed, consider notifying Stripe support",
        "6. Add .env to .gitignore",
    ],
    "slack": [
        "1. Go to api.slack.com → Your Apps → select app → OAuth & Permissions",
        "2. Click 'Revoke Token'",
        "3. Reinstall the app to generate a new token",
        "4. Update your .env and any integrations",
        "5. Check Slack audit logs for suspicious bot activity",
    ],
    "sendgrid": [
        "1. Go to app.sendgrid.com → Settings → API Keys",
        "2. Delete the exposed key",
        "3. Create a new API key with minimal permissions",
        "4. Update your .env and email service configs",
        "5. Check SendGrid Activity Feed for unexpected sends",
    ],
    "twilio": [
        "1. Go to console.twilio.com → Account → API keys & tokens",
        "2. Revoke the exposed key",
        "3. Generate a new API key",
        "4. Update your .env and any Twilio integrations",
        "5. Check Twilio Monitor for suspicious calls/messages",
    ],
    "jwt": [
        "1. Rotate your JWT secret immediately — all existing tokens are now invalid",
        "2. Update JWT_SECRET in your .env with a strong random value (32+ chars)",
        "3. Force all users to re-login (existing sessions are compromised)",
        "4. Add .env to .gitignore",
    ],
    "generic": [
        "1. Assume this credential is compromised — revoke it immediately",
        "2. Log into the service that issued this key and revoke/rotate it",
        "3. Generate a new credential and update your .env",
        "4. Check the service's audit log for unauthorised activity",
        "5. Add .env to .gitignore to prevent future leaks",
    ],
}


def get_remediation(finding: dict[str, Any]) -> str:
    """Return a short notification message for a secret finding."""
    rule, file_ = _parse_finding(finding)
    steps = _steps_for_rule(rule)
    # Notification is space-limited — return first actionable step
    return f"🚨 {rule.upper()} key exposed in {file_}. {steps[0]}"


def get_full_remediation(finding: dict[str, Any]) -> str:
    """Return full multi-line remediation for logging."""
    rule, file_ = _parse_finding(finding)
    steps = _steps_for_rule(rule)
    lines = [
        f"🚨 SECRET EXPOSED: {rule.upper()} in {file_}",
        "",
        *steps,
        "",
        "See ~/.security-autopilot/secret-alerts.log for history.",
    ]
    return "\n".join(lines)


def log_secret_alert(project_path: str, finding: dict[str, Any]) -> None:
    """Append full remediation steps to the persistent alerts log."""
    _ALERTS_LOG.parent.mkdir(parents=True, exist_ok=True)
    rule, file_ = _parse_finding(finding)
    steps = _steps_for_rule(rule)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"{'='*60}",
        f"🚨 {ts}",
        f"Project : {project_path}",
        f"Secret  : {rule.upper()}",
        f"File    : {file_}",
        "",
        "Steps to fix:",
        *[f"  {s}" for s in steps],
        "",
    ]

    with _ALERTS_LOG.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    log.warning("Secret alert logged to %s", _ALERTS_LOG)


def _parse_finding(finding: dict[str, Any]) -> tuple[str, str]:
    """Extract (rule, filename) from a gitleaks finding title."""
    title = finding.get("title", "")
    # "Exposed aws-access-token secret in .env"
    m = re.search(r"Exposed\s+(.+?)\s+secret\s+in\s+(.+)", title, re.IGNORECASE)
    if m:
        return m.group(1).lower(), m.group(2).strip()
    return "secret", finding.get("file", "unknown file") or "unknown file"


def _steps_for_rule(rule: str) -> list[str]:
    """Match rule to closest known remediation, fall back to generic."""
    rule_lower = rule.lower()
    for key, steps in _REMEDIATION.items():
        if key in rule_lower:
            return steps
    return _REMEDIATION["generic"]
