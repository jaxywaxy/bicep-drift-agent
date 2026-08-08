"""
Configuration management for the drift agent example.

Tunable runtime parameters, centralized with environment-variable overrides so
operators can adjust behavior without changing code. Every value here is wired
into the code that uses it — see the referenced call sites.
"""

import json
import logging
import os

logger = logging.getLogger(__name__)

# ===== Bicep Compilation =====

# `or` not a get-default: CI hands an UNSET repo variable through as an empty
# string, and int("") raises at import - which would kill every scan rather
# than fall back. Empty means unset, everywhere in this file.
BICEP_BUILD_TIMEOUT = int(os.environ.get("DRIFT_BICEP_TIMEOUT", "").strip() or "120")
"""Timeout in seconds for `az bicep build` (tools/compile_bicep.py)."""

# ===== Webhook Notifications =====

WEBHOOK_TIMEOUT_SECONDS = int(os.environ.get("DRIFT_WEBHOOK_TIMEOUT", "").strip() or "10")
"""Timeout in seconds for Slack/Teams webhook POSTs (tools/send_notifications.py)."""

# ===== Change-Origin Classification =====

AUTHORIZED_DEPLOYERS = frozenset(
    p.strip().lower()
    for p in os.environ.get("DRIFT_AUTHORIZED_DEPLOYERS", "").split(",")
    if p.strip()
)
"""Identities whose Activity Log changes are authorized IaC deployments, not
manual drift (tools/change_origin.py). Comma-separated object IDs, appIds or
UPNs - whatever form the client's Activity Log 'caller' takes. The identity
the scan itself runs as is ALWAYS treated as a deployer automatically
(tools/activity_log.py:detect_scanning_identity), so this is only needed when
a client deploys with a different identity than they scan with."""

# ===== Ownership =====

OWNERSHIP_MODEL_ENV = "DRIFT_OWNERSHIP_MODEL"
"""Who owns a resource nothing else classifies: `platform` or `workload`.

Defaults to `workload`, which is the historical behaviour and right for a
workload landing zone. Set it to `platform` for an enterprise/platform LZ, where
the platform team owns the whole subscription and the app-team default routes
every finding to a team that cannot act on it (tools/ownership.py)."""

MODULE_OWNERS_ENV = "DRIFT_MODULE_OWNERS"
"""JSON mapping a Bicep module glob to an owner, e.g.

    {"networking": "platform", "logging": "platform", "apps": "workload"}

The module a resource is declared in says which codebase - and so which team -
owns it. That beats classifying by resource TYPE, which is identical whoever
deployed it. Longest matching pattern wins. Unmapped modules fall through to the
type rules and then to DRIFT_OWNERSHIP_MODEL."""


def ownership_default_owner() -> str:
    """The owner to fall back on. Invalid values warn and keep the default."""
    raw = os.environ.get(OWNERSHIP_MODEL_ENV, "").strip().lower()
    if not raw:
        return "workload"
    if raw not in ("platform", "workload"):
        logger.warning("%s must be 'platform' or 'workload', got %r - using 'workload'",
                       OWNERSHIP_MODEL_ENV, raw)
        return "workload"
    return raw


def module_owners() -> dict[str, str]:
    """Parse DRIFT_MODULE_OWNERS. Returns {} and warns on anything malformed.

    Bad config must not fail a scan, and must not half-apply: a partially
    honoured ownership map would route some findings correctly and others
    silently to the wrong team, which is harder to notice than no mapping.
    """
    raw = os.environ.get(MODULE_OWNERS_ENV, "").strip()
    if not raw or raw == "null":
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError as e:
        logger.warning("%s is not valid JSON, ignoring it: %s", MODULE_OWNERS_ENV, e)
        return {}
    if not isinstance(parsed, dict):
        logger.warning("%s must be a JSON object of module-glob -> owner, got %s",
                       MODULE_OWNERS_ENV, type(parsed).__name__)
        return {}

    out: dict[str, str] = {}
    for pattern, owner in parsed.items():
        owner_l = str(owner).strip().lower()
        if not (isinstance(pattern, str) and pattern.strip()):
            logger.warning("%s: skipping row with an empty module pattern", MODULE_OWNERS_ENV)
            continue
        if owner_l not in ("platform", "workload"):
            logger.warning("%s: skipping %r - owner must be 'platform' or 'workload', got %r",
                           MODULE_OWNERS_ENV, pattern, owner)
            continue
        out[pattern.strip()] = owner_l
    return out


# ===== LLM Pricing =====

MODEL_PRICING_ENV = "DRIFT_MODEL_PRICING"
"""JSON overriding and extending the built-in price table (agent/usage.py).

Maps a model-id PREFIX to [input, output] USD per million tokens:

    {"gpt-5-mini": [0.25, 2.00], "claude-opus-4-8": [5.00, 25.00]}

Prices move and new models appear between releases, and the built-in table only
ever knew Anthropic's - so a provider swap left the cost line reading "unknown".
This keeps it current without a code change: set it as a repo variable. Rows
here beat built-ins, and a model with no row anywhere still reports tokens,
just not dollars."""


def model_pricing_overrides() -> dict[str, tuple[float, float]]:
    """Parse DRIFT_MODEL_PRICING. Returns {} and warns on anything malformed.

    Read per call rather than cached at import so an operator changing the
    variable does not need a restart, and so tests can set it.

    A pricing typo must never fail a scan - dollars are a reporting nicety and
    the drift result is the product. Discarding a bad row leaves the cost
    "unknown", which is the honest answer; the alternative is charging someone
    against a number we only half-parsed.
    """
    raw = os.environ.get(MODEL_PRICING_ENV, "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError as e:
        logger.warning("%s is not valid JSON, ignoring it: %s", MODEL_PRICING_ENV, e)
        return {}
    if not isinstance(parsed, dict):
        logger.warning("%s must be a JSON object of model-prefix -> [input, output], got %s",
                       MODEL_PRICING_ENV, type(parsed).__name__)
        return {}

    out: dict[str, tuple[float, float]] = {}
    for prefix, prices in parsed.items():
        if not (isinstance(prefix, str) and prefix.strip()):
            logger.warning("%s: skipping row with an empty model prefix", MODEL_PRICING_ENV)
            continue
        if not (isinstance(prices, (list, tuple)) and len(prices) == 2):
            logger.warning("%s: skipping %r - expected [input, output] per million tokens",
                           MODEL_PRICING_ENV, prefix)
            continue
        # bool is an int subclass; True as a price is a typo, not a price.
        if any(isinstance(p, bool) or not isinstance(p, (int, float)) or p < 0 for p in prices):
            logger.warning("%s: skipping %r - prices must be non-negative numbers, got %r",
                           MODEL_PRICING_ENV, prefix, list(prices))
            continue
        out[prefix.strip()] = (float(prices[0]), float(prices[1]))
    return out


# ===== Logging =====

LOG_LEVEL = (os.environ.get("DRIFT_LOG_LEVEL", "").strip() or "INFO").upper()
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

    # Surface a pricing variable that is set but unusable. It is ignored either
    # way, but silently ignored means the cost line reads "unknown" and nobody
    # knows the override was the reason.
    if os.environ.get(MODEL_PRICING_ENV, "").strip() and not model_pricing_overrides():
        warnings.append(f"{MODEL_PRICING_ENV} is set but no usable price rows were parsed from it")

    return warnings
