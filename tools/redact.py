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


def _is_appsettings_resource(obj: Any) -> bool:
    """True for a Microsoft.Web/sites/config '<site>/appsettings' resource.

    App setting NAMES are arbitrary and user-chosen - AzureWebJobsStorage,
    APPINSIGHTS_INSTRUMENTATIONKEY, DOCKER_REGISTRY_SERVER_PASSWORD, MY_DB_CONN -
    so key-name matching can never be complete for them. Seen live: a function
    app's AzureWebJobsStorage held a full storage connection string (live
    AccountKey=...) and sailed through _is_secret_key into the report artifact.
    EVERY app setting value is therefore treated as a secret.

    Safe to redact wholesale: the comparator reduces BOTH sides to KEY SETS
    (property_drift.compare_properties) and never reads a value, so the key set
    - which is all that is compared - is preserved.
    """
    return (
        isinstance(obj, dict)
        and str(obj.get("type", "")).lower() == "microsoft.web/sites/config"
        and str(obj.get("name", "")).lower().endswith("/appsettings")
    )


def redact_secrets(obj: Any) -> Any:
    """Return a deep copy of obj with secret-bearing values replaced by REDACTED.

    Walks dicts and lists recursively. Non-None values under a secret key are
    replaced; None is preserved (Azure returns null for write-only props, and a
    null is not a leaked secret — keeping it avoids masking "not set" as "set").
    Scalars and other types are returned unchanged.
    """
    if isinstance(obj, dict):
        # App settings: redact every VALUE, preserve every KEY (see
        # _is_appsettings_resource). Handled at the resource level because the
        # setting names themselves carry no signal.
        if _is_appsettings_resource(obj):
            redacted = {k: redact_secrets(v) for k, v in obj.items() if k != "properties"}
            props = obj.get("properties")
            redacted["properties"] = (
                {k: REDACTED for k in props} if isinstance(props, dict) else props
            )
            return redacted

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
