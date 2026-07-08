"""
tools/redact.py

Redact secret-bearing property values before they are persisted to disk.

The raw drift report dumps the fully-resolved Bicep resources (arm_resources)
and live Azure state. Property COMPARISON already skips write-only secrets
(see property_drift.WRITE_ONLY_PROPERTIES), but the raw dump bypasses that.
If a parameters.json / .bicepparam supplies a literal secret (e.g.
administratorLoginPassword), the resolved value would otherwise land in
reports/<rg>-drift.json in plaintext. This module scrubs those values at the
single write point so they never touch the filesystem or CI artifacts.
"""

from typing import Any

REDACTED = "***REDACTED***"

# Keys whose values are secrets regardless of nesting. Matched case-insensitively
# against the EXACT key name. Kept exact (not substring) so benign keys that merely
# contain "password" — e.g. disablePasswordAuthentication (a bool) — are untouched.
_SECRET_KEYS_EXACT = frozenset(
    {
        "administratorloginpassword",
        "adminpassword",
        "password",
        "secret",
        "clientsecret",
        "connectionstring",
        "primaryconnectionstring",
        "secondaryconnectionstring",
        "primarykey",
        "secondarykey",
        "accountkey",
        "accesskey",
        "sastoken",
        "sharedaccesskey",
    }
)

# Suffixes that reliably denote a secret value (covers vendor-specific names like
# runtimeADUserPassword, storageAccountConnectionString, etc.).
_SECRET_KEY_SUFFIXES = ("password", "connectionstring", "secret")


def _is_secret_key(key: str) -> bool:
    k = key.lower()
    if k in _SECRET_KEYS_EXACT:
        return True
    return any(k.endswith(suffix) for suffix in _SECRET_KEY_SUFFIXES)


def redact_secrets(obj: Any) -> Any:
    """Return a deep copy of obj with secret-bearing values replaced by REDACTED.

    Walks dicts and lists recursively. Non-None values under a secret key are
    replaced; None is preserved (Azure returns null for write-only props, and a
    null is not a leaked secret — keeping it avoids masking "not set" as "set").
    Scalars and other types are returned unchanged.
    """
    if isinstance(obj, dict):
        redacted = {}
        for key, value in obj.items():
            if isinstance(key, str) and _is_secret_key(key) and value is not None \
                    and not isinstance(value, (dict, list)):
                redacted[key] = REDACTED
            else:
                redacted[key] = redact_secrets(value)
        return redacted
    if isinstance(obj, list):
        return [redact_secrets(item) for item in obj]
    return obj
