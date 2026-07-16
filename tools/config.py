"""
Configuration management for the drift agent example.

Tunable runtime parameters, centralized with environment-variable overrides so
operators can adjust behavior without changing code. Every value here is wired
into the code that uses it — see the referenced call sites.
"""

import os

# ===== Bicep Compilation =====

BICEP_BUILD_TIMEOUT = int(os.environ.get("DRIFT_BICEP_TIMEOUT", "120"))
"""Timeout in seconds for `az bicep build` (tools/compile_bicep.py)."""

# ===== Webhook Notifications =====

WEBHOOK_TIMEOUT_SECONDS = int(os.environ.get("DRIFT_WEBHOOK_TIMEOUT", "10"))
"""Timeout in seconds for Slack/Teams webhook POSTs (tools/send_notifications.py)."""

# ===== Logging =====

LOG_LEVEL = os.environ.get("DRIFT_LOG_LEVEL", "INFO").upper()
"""Default logging level (DEBUG/INFO/WARNING/ERROR); used by the entry points."""


def validate_config() -> list[str]:
    """Validate configuration values and return a list of warning messages.

    Returns:
        List of validation warnings (empty if all values are valid).
    """
    warnings = []

    if BICEP_BUILD_TIMEOUT < 1:
        warnings.append(f"DRIFT_BICEP_TIMEOUT should be >= 1, got {BICEP_BUILD_TIMEOUT}")

    if WEBHOOK_TIMEOUT_SECONDS < 1:
        warnings.append(f"DRIFT_WEBHOOK_TIMEOUT should be >= 1, got {WEBHOOK_TIMEOUT_SECONDS}")

    if LOG_LEVEL not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        warnings.append(f"DRIFT_LOG_LEVEL should be DEBUG/INFO/WARNING/ERROR, got {LOG_LEVEL}")

    return warnings
