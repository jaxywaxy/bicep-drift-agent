"""
Configuration management for the bicep-drift-agent.

All tunable parameters are centralized here with environment variable overrides.
This allows operators to customize behavior without changing code.
"""

import os
from typing import Optional

# ===== Azure SDK Retry Configuration =====
# Controls exponential backoff retry behavior for transient Azure API failures

AZURE_RETRY_MAX_ATTEMPTS = int(os.environ.get("DRIFT_AZURE_RETRY_MAX", "3"))
"""Maximum number of retry attempts for transient Azure SDK failures (429, 5xx)."""

AZURE_RETRY_INITIAL_DELAY = float(os.environ.get("DRIFT_AZURE_RETRY_INITIAL_DELAY", "1.0"))
"""Initial delay in seconds for first retry (doubles after each attempt)."""

# ===== Webhook Configuration =====
# Notification delivery timeout and behavior

WEBHOOK_TIMEOUT_SECONDS = int(os.environ.get("DRIFT_WEBHOOK_TIMEOUT", "10"))
"""Timeout in seconds for webhook HTTP requests."""

# ===== Resource Matching Configuration =====
# Tunable thresholds for resource matching confidence scores

CONFIDENCE_SCORE_EXACT_MATCH = float(os.environ.get("DRIFT_CONF_EXACT_MATCH", "0.95"))
"""Confidence score for exact name matches."""

CONFIDENCE_SCORE_PREFIX_MATCH = float(os.environ.get("DRIFT_CONF_PREFIX_MATCH", "0.85"))
"""Confidence score for prefix-based matches (e.g., parameter-based names)."""

CONFIDENCE_SCORE_CONTEXTUAL = float(os.environ.get("DRIFT_CONF_CONTEXTUAL", "0.90"))
"""Confidence score for contextual matching (via related resources)."""

CONFIDENCE_SCORE_FUZZY_THRESHOLD = float(os.environ.get("DRIFT_CONF_FUZZY_THRESHOLD", "0.60"))
"""Minimum confidence score for fuzzy token-based matching."""

CONFIDENCE_SCORE_FALLBACK = float(os.environ.get("DRIFT_CONF_FALLBACK", "0.25"))
"""Baseline confidence score for unmatched resources."""

# ===== Bicep Compilation Configuration =====

BICEP_BUILD_TIMEOUT = int(os.environ.get("DRIFT_BICEP_TIMEOUT", "60"))
"""Timeout in seconds for az bicep build operations."""

# ===== Logging Configuration =====

LOG_LEVEL = os.environ.get("DRIFT_LOG_LEVEL", "INFO").upper()
"""Logging level (DEBUG, INFO, WARNING, ERROR)."""

# ===== Property Comparison Configuration =====

CRITICAL_PROPERTIES_FOR_DRIFT = [
    # Location and kind are fundamental
    "location",
    "kind",
    # Storage
    "sku",
    # Compute
    "vmSize",
    "osProfile",
    # Network
    "networkProfile",
    "ipConfigurations",
    # Database
    "administratorLoginPassword",
]
"""Properties that always trigger drift if changed (location, kind, etc)."""

# ===== Feature Flags =====
# Enable/disable advanced features

ENABLE_SMART_MATCHING = os.environ.get("DRIFT_ENABLE_SMART_MATCHING", "true").lower() == "true"
"""Enable contextual and fuzzy resource matching for parameter-based names."""

ENABLE_PROPERTY_ENRICHMENT = os.environ.get("DRIFT_ENABLE_ENRICHMENT", "true").lower() == "true"
"""Enable resource property enrichment (SKU, storage, network details)."""


def validate_config() -> list[str]:
    """Validate configuration values and return list of warnings.

    Returns:
        List of validation warning messages (empty if all valid)
    """
    warnings = []

    # Validate numeric ranges
    if AZURE_RETRY_MAX_ATTEMPTS < 0:
        warnings.append(f"DRIFT_AZURE_RETRY_MAX should be >= 0, got {AZURE_RETRY_MAX_ATTEMPTS}")

    if AZURE_RETRY_INITIAL_DELAY < 0:
        warnings.append(f"DRIFT_AZURE_RETRY_INITIAL_DELAY should be > 0, got {AZURE_RETRY_INITIAL_DELAY}")

    if WEBHOOK_TIMEOUT_SECONDS < 1:
        warnings.append(f"DRIFT_WEBHOOK_TIMEOUT should be >= 1, got {WEBHOOK_TIMEOUT_SECONDS}")

    # Validate confidence scores (should be 0.0-1.0)
    for score_name, score_value in [
        ("EXACT_MATCH", CONFIDENCE_SCORE_EXACT_MATCH),
        ("PREFIX_MATCH", CONFIDENCE_SCORE_PREFIX_MATCH),
        ("CONTEXTUAL", CONFIDENCE_SCORE_CONTEXTUAL),
        ("FUZZY_THRESHOLD", CONFIDENCE_SCORE_FUZZY_THRESHOLD),
        ("FALLBACK", CONFIDENCE_SCORE_FALLBACK),
    ]:
        if not 0.0 <= score_value <= 1.0:
            warnings.append(f"DRIFT_CONF_{score_name} should be between 0.0 and 1.0, got {score_value}")

    # Validate log level
    if LOG_LEVEL not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        warnings.append(f"DRIFT_LOG_LEVEL should be DEBUG/INFO/WARNING/ERROR, got {LOG_LEVEL}")

    return warnings
