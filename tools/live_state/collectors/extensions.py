"""Extension resources (diagnostic settings, DCR associations) attached to a
target resource. Not Resource Graph rows; a deleted one is a silenced
audit/telemetry feed - the drift that must page someone.

Bicep declares them as extension resources with a 'scope';
qualify_extension_resource_names() aligns those to the '{scope}/{name}' form
the live expansion produces.
"""

import json as _json
import logging
import urllib.request

from azure.identity import DefaultAzureCredential

from ...http_util import urlopen_checked

logger = logging.getLogger(__name__)


# Types that commonly carry diagnostic settings - queried per resource (N calls),
# so scoped to a curated set rather than every row.
_DIAGNOSTIC_PARENT_TYPES = {
    "microsoft.keyvault/vaults",
    "microsoft.storage/storageaccounts",
    "microsoft.web/sites",
    "microsoft.sql/servers/databases",
    "microsoft.eventhub/namespaces",
    "microsoft.servicebus/namespaces",
    "microsoft.documentdb/databaseaccounts",
    "microsoft.cognitiveservices/accounts",
    "microsoft.network/networksecuritygroups",
    "microsoft.network/azurefirewalls",
    "microsoft.network/applicationgateways",
    "microsoft.containerservice/managedclusters",
    "microsoft.operationalinsights/workspaces",
    "microsoft.logic/workflows",
}


# Data Collection Rule associations link a DCR to a monitored resource (chiefly
# VMs/VMSS). A deleted association silences guest telemetry - the modern
# equivalent of a deleted diagnostic setting.
_DCR_ASSOCIATION_PARENT_TYPES = {
    "microsoft.compute/virtualmachines",
    "microsoft.compute/virtualmachinescalesets",
    "microsoft.hybridcompute/machines",  # Arc-enabled servers
}

# Extension-resource types the agent expands per-resource, keyed by the child
# type -> (parent-type set, provider-relative list path, api-version, log label).
_EXTENSION_EXPANSION_SPECS = {
    "Microsoft.Insights/diagnosticSettings": (
        _DIAGNOSTIC_PARENT_TYPES, "providers/Microsoft.Insights/diagnosticSettings",
        "2021-05-01-preview", "diagnostic setting"),
    "Microsoft.Insights/dataCollectionRuleAssociations": (
        _DCR_ASSOCIATION_PARENT_TYPES, "providers/Microsoft.Insights/dataCollectionRuleAssociations",
        "2022-06-01", "DCR association"),
}

# The extension types whose bicep resources carry a 'scope' field to qualify.
_EXTENSION_TYPES_LOWER = {t.lower() for t in _EXTENSION_EXPANSION_SPECS}


def _expand_extension_resources(resources: list[dict], token: str | None = None) -> list[dict]:
    """Expand per-resource extension children (diagnostic settings, DCR
    associations) named '{resource}/{name}'."""
    active = {
        child_type: spec for child_type, spec in _EXTENSION_EXPANSION_SPECS.items()
        if any((r.get("type") or "").lower() in spec[0] for r in resources)
    }
    if not active:
        return []
    try:
        if not token:
            token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
    except Exception as e:
        logger.warning(f"Could not acquire token for extension-resource expansion: {e}")
        return []

    children: list[dict] = []
    for child_type, (parent_types, path, api, label) in active.items():
        parents = [
            r for r in resources
            if (r.get("type") or "").lower() in parent_types and r.get("id")
        ]
        count = 0
        for parent in parents[:60]:  # hard cap on the N+1 fan-out
            pid, pname = parent["id"], parent.get("name", "")
            try:
                req = urllib.request.Request(
                    f"https://management.azure.com{pid}/{path}?api-version={api}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                with urlopen_checked(req, timeout=30) as resp:
                    items = _json.load(resp).get("value", [])
            except Exception as e:
                logger.debug(f"Could not list {label} for {pname}: {e}")
                continue
            for item in items:
                children.append({
                    "type": child_type,
                    "name": f"{pname}/{item.get('name', '')}",
                    "location": None, "tags": {}, "sku": None, "kind": None,
                    "properties": item.get("properties", {}) or {},
                    "id": item.get("id"), "resource_group": parent.get("resource_group"),
                })
                count += 1
        if count:
            logger.info(f"Expanded {count} {label}(s)")
    return children


# Back-compat alias (used by tests and callers that expanded diag settings only).
def _expand_diagnostic_settings(resources: list[dict], token: str | None = None) -> list[dict]:
    return _expand_extension_resources(resources, token=token)


def qualify_extension_resource_names(arm_resources: list[dict]) -> None:
    """Rewrite bicep extension resources (diagnostic settings, DCR associations)
    to '{scope-leaf}/{name}' so they match the live expansion form.

    A bicep extension resource compiles with a plain name plus a 'scope' field
    ('Microsoft.Storage/storageAccounts/stX'); live expansion names them
    '{resourceName}/{settingName}'. Mutates in place.
    """
    for r in arm_resources:
        if (r.get("type") or "").lower() not in _EXTENSION_TYPES_LOWER:
            continue
        scope = str(r.get("scope") or "")
        if not scope or "/" in (r.get("name") or ""):
            continue
        scope_leaf = scope.split("/")[-1]
        if scope_leaf:
            r["name"] = f"{scope_leaf}/{r['name']}"


# Back-compat alias.
qualify_diagnostic_setting_names = qualify_extension_resource_names
